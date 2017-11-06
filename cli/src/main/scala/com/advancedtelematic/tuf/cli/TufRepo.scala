package com.advancedtelematic.tuf.cli

import java.io._
import java.net.URI
import java.nio.file.{Files, Path}
import java.time.{Instant, Period}
import java.util.zip.{ZipEntry, ZipFile, ZipOutputStream}

import scala.collection.JavaConversions._
import cats.syntax.either._
import cats.syntax.option._
import com.advancedtelematic.libtuf.crypt.TufCrypto
import com.advancedtelematic.libtuf.data.ClientDataType.{ClientTargetItem, ETag, RoleKeys, RoleTypeToMetaPathOp, RootRole, TargetCustom, TargetsRole, VersionedRole}
import com.advancedtelematic.libtuf.data.TufDataType.{HardwareIdentifier, KeyId, KeyType, RoleType, SignedPayload, TargetFormat, TargetName, TargetVersion, TufKey, TufPrivateKey, ValidTargetFilename}
import com.advancedtelematic.libats.data.DataType.{HashMethod, ValidChecksum}
import com.advancedtelematic.libtuf.data.TufCodecs._
import com.advancedtelematic.libtuf.data.ClientCodecs._
import com.advancedtelematic.libtuf.data.TufDataType.RoleType.RoleType
import com.advancedtelematic.libtuf.reposerver.UserReposerverClient
import com.advancedtelematic.tuf.cli.DataType.{AuthConfig, KeyName, RepoName}
import TryToFuture._
import cats.data.Validated.{Invalid, Valid}
import com.advancedtelematic.libtuf.data.TufDataType.TargetFormat.TargetFormat
import eu.timepit.refined.refineV
import eu.timepit.refined.api.Refined
import io.circe.{Decoder, Encoder, Json}
import io.circe.jawn.{parse, parseFile}
import io.circe.syntax._
import org.slf4j.LoggerFactory
import com.advancedtelematic.tuf.cli.TufRepo.{EtagsNotFound, TargetsPullError, UnknownInitFile}

import scala.concurrent.{ExecutionContext, Future}
import scala.io.Source
import scala.util.control.NoStackTrace
import scala.util.{Failure, Try}

object TufRepo {
  case object EtagsNotFound extends Exception(
    "Could not find targets etags file. You need this to push a new targets file. Etags can be obtained using the pull command"
  ) with NoStackTrace

  case class UnknownInitFile(path: Path) extends Exception(
    s"unknown file extension for repo init: $path"
  )

  case class TargetsPullError(msg: String) extends Exception(msg) with NoStackTrace
}

class TufRepo(val name: RepoName, val repoPath: Path)(implicit ec: ExecutionContext) {
  import CliCodecs._

  lazy val keyStorage = new CliKeyStorage(repoPath)

  private lazy val log = LoggerFactory.getLogger(this.getClass)

  private lazy val rolesPath = repoPath.resolve("roles")

  private val DEFAULT_EXPIRE_TIME = Period.ofDays(365)

  val zipTargetKeyName = KeyName("targets")

  private def readJsonFrom[T](is: InputStream)(implicit decoder: Decoder[T]): Try[T] = {
    parse(Source.fromInputStream(is).mkString).flatMap(_.as[T](decoder)).toTry
  }

  def initFromAuthJson(authJson: File): Try[Unit] =
    for {
      json <- parseFile(authJson).toTry
      authConfig <- json.as[AuthConfig](authConfigDecoder.prepare(_.downField("oauth2"))).toTry
      _ <- Try(Files.write(repoPath.resolve("auth.json"), authConfig.asJson.noSpaces.getBytes))
    } yield ()

  def initFromZip(path: Path): Try[Unit] = {
    // copy whole ZIP file into repo
    Files.copy(path, repoPath.resolve("credentials.zip"))

    def writeAuthFile(src: ZipFile): Try[Unit] = for {
      is <- Try(src.getInputStream(src.getEntry("treehub.json")))
      decoder = authConfigDecoder.prepare(_.downField("oauth2"))
      authConfig ← readJsonFrom[AuthConfig](is)(decoder)
      _ ← Try(Files.write(repoPath.resolve("auth.json"), authConfig.asJson.noSpaces.getBytes))
    } yield ()

    def writeTargetKeys(src: ZipFile): Try[Unit] = for {
      pubKeyIs <- Try(src.getInputStream(src.getEntry(zipTargetKeyName.publicKeyName)))
      pubKey <- readJsonFrom[TufKey](pubKeyIs)

      privateKeyIs <- Try(src.getInputStream(src.getEntry(zipTargetKeyName.privateKeyName)))
      privKey <- readJsonFrom[TufPrivateKey](privateKeyIs)

      _ <- keyStorage.writeKeys(zipTargetKeyName, pubKey, privKey)
    } yield ()

    for {
      src ← Try(new ZipFile(path.toFile))
      _ <- writeAuthFile(src)
      _ <- writeTargetKeys(src).recover { case ex =>
        log.warn(s"Could not read/write target keys from credentials zip file: ${ex.getMessage}. Continuing.")
      }
      _ = Try(src.close())
    } yield ()
  }

  def init(credentialsPath: Path): Try[Unit] =
    Try {
      Files.createDirectories(repoPath.resolve("keys"))
      credentialsPath.getFileName.toString
    }.flatMap { name =>
      if (name.endsWith(".json")) {
        initFromAuthJson(credentialsPath.toFile)
      } else if (name.endsWith(".zip")) {
        initFromZip(credentialsPath)
      } else {
        Failure(UnknownInitFile(credentialsPath))
      }
    }

  def initTargets(version: Int, expires: Instant): Try[Path] = {
    val emptyTargets = TargetsRole(expires, Map.empty, version)
    writeUnsignedRole(emptyTargets)
  }

  def addTarget(name: TargetName, version: TargetVersion, length: Int, checksum: Refined[String, ValidChecksum],
                hardwareIds: List[HardwareIdentifier], url: URI, format: TargetFormat): Try[Path] = {
    for {
      targetsRole <- readUnsignedRole[TargetsRole](RoleType.TARGETS)
      targetFilename <- refineV[ValidTargetFilename](s"${name.value}-${version.value}").leftMap(s => new IllegalArgumentException(s)).toTry
      newTargetRole = {
        val custom = TargetCustom(name, version, hardwareIds, format.some, url.some)
        val clientHashes = Map(HashMethod.SHA256 -> checksum)
        val newTarget = ClientTargetItem(clientHashes, length, custom.asJson.some)

        targetsRole.copy(targets = targetsRole.targets + (targetFilename -> newTarget))
      }
      path <- writeUnsignedRole(newTargetRole)
    } yield path
  }

  private def writeTargets(targets: SignedPayload[TargetsRole], etag: ETag): Try[Unit] =
    writeSignedRole(targets).flatMap(_ => writeEtag(etag))

  def pullTargets(reposerverClient: UserReposerverClient, rootRole: RootRole): Future[SignedPayload[TargetsRole]] =
    reposerverClient.targets().flatMap {
      case reposerverClient.TargetsResponse(targets, etag) =>
        val roleValidation = TufCrypto.payloadSignatureIsValid(rootRole, targets)

        roleValidation match {
          case Valid(_) if etag.isDefined => writeTargets(targets, etag.get).map(_ => targets).toFuture
          case Valid(_) => Future.failed(TargetsPullError("Did not receive valid etag from reposerver"))
          case Invalid(s) => Future.failed(TargetsPullError(s.toList.mkString(", ")))
        }
    }

  def pushTargets(reposerverClient: UserReposerverClient): Future[SignedPayload[TargetsRole]] =
    readSignedRole[TargetsRole](RoleType.TARGETS).toFuture.flatMap { targets =>
      log.debug(s"pushing ${targets.asJson.spaces2}")

      for {
        etag <- readEtag[TargetsRole](RoleType.TARGETS).toFuture
        _ <- reposerverClient.pushTargets(targets, etag.some)
      } yield targets
    }

  def signTargets(targetsKey: KeyName): Try[Path] =
    for {
      (pub, priv) <- keyStorage.readKeyPair(targetsKey)
      unsigned <- readUnsignedRole[TargetsRole](RoleType.TARGETS) // TODO: Why do we need both?
      newUnsigned = unsigned.copy(version = unsigned.version + 1)
      sig = TufCrypto.signPayload(priv, newUnsigned).toClient(pub.id)
      signedRole = SignedPayload(Seq(sig), newUnsigned)
      _ <- writeUnsignedRole(signedRole.signed)
      path <- writeSignedRole(signedRole)
    } yield path

  private def deleteOrReadKey(reposerverClient: UserReposerverClient, keyName: KeyName, keyId: KeyId): Future[TufPrivateKey] = {
    keyStorage.readPrivateKey(keyName).toFuture.recoverWith { case _ =>
      log.info(s"Could not read old private key locally, fetching/deleting from server")
      reposerverClient.deleteKey(keyId)
    }
  }

  def readUnsignedRole[T <: VersionedRole : Decoder](roleType: RoleType): Try[T] = {
    val path = rolesPath.resolve("unsigned").resolve(roleType.toMetaPath.value)
    parseFile(path.toFile).flatMap(_.as[T]).toTry
  }

  def readSignedRole[T <: VersionedRole](roleType: RoleType)(implicit ev: Decoder[SignedPayload[T]]): Try[SignedPayload[T]] = {
    val path = rolesPath.resolve(roleType.toMetaPath.value)
    parseFile(path.toFile).flatMap(_.as[SignedPayload[T]]).toTry
  }

  private def readEtag[T <: VersionedRole](roleType: RoleType): Try[ETag] = Try {
    val lines = Files.readAllLines(rolesPath.resolve(roleType.toETagPath))
    assert(lines.tail.isEmpty)
    ETag(lines.head)
  }.recoverWith {
    case _: FileNotFoundException => Failure(EtagsNotFound)
  }

  private def writeEtag(etag: ETag): Try[Unit] = Try {
    Files.write(rolesPath.resolve(RoleType.TARGETS.toETagPath), etag.value.getBytes)
  }

  private def writeUnsignedRole[T <: VersionedRole : Encoder](role: T): Try[Path] =
    writeRole(rolesPath.resolve("unsigned"), role.roleType, role)

  private def writeSignedRole[T <: VersionedRole : Encoder](signedPayload: SignedPayload[T]): Try[Path] =
    writeRole(rolesPath, signedPayload.signed.roleType, signedPayload)

  private def writeRole[T: Encoder](path: Path, roleType: RoleType, payload: T): Try[Path] = Try {
    Files.createDirectories(path)
    val rolePath = path.resolve(roleType.toMetaPath.value)
    Files.write(rolePath, payload.asJson.spaces2.getBytes)
    rolePath
  }

  def genKeys(name: KeyName, keyType: KeyType, keySize: Int): Try[(TufKey, TufPrivateKey)] =
    keyStorage.genKeys(name, keyType, keySize)

  def rotateRoot(repoClient: UserReposerverClient,
                 newRootName: KeyName,
                 oldRootName: KeyName,
                 newTargetsName: KeyName,
                 oldKeyId: Option[KeyId]): Future[SignedPayload[RootRole]] = {
    for {
      (newRootPubKey, newRootPrivKey) <- keyStorage.readKeyPair(newRootName).toFuture
      (newTargetsPubKey, _) <- keyStorage.readKeyPair(newTargetsName).toFuture
      oldRootRole <- repoClient.root().map(_.signed)
      oldTargets <- pullTargets(repoClient, oldRootRole)
      _ <- writeUnsignedRole(oldTargets.signed).toFuture
      oldRootPubKeyId = oldKeyId.getOrElse(oldRootRole.roles(RoleType.ROOT).keyids.last)
      oldTargetsKeyIds = oldRootRole.roles(RoleType.TARGETS).keyids
      oldRootPubKey = oldRootRole.keys(oldRootPubKeyId)
      oldRootPrivKey <- deleteOrReadKey(repoClient, oldRootName, oldRootPubKeyId)
      _ <- keyStorage.writeKeys(oldRootName, oldRootPubKey, oldRootPrivKey).toFuture
      newKeySet = (oldRootRole.keys -- (oldTargetsKeyIds :+ oldRootPubKeyId)) ++ Map(newRootPubKey.id -> newRootPubKey, newTargetsPubKey.id -> newTargetsPubKey)
      newRootRoleKeys = RoleKeys(Seq(newRootPubKey.id), threshold = 1)
      newTargetsRoleKeys = RoleKeys(Seq(newTargetsPubKey.id), threshold = 1)
      newRootRoleMap = oldRootRole.roles ++ Map(RoleType.ROOT -> newRootRoleKeys, RoleType.TARGETS -> newTargetsRoleKeys)
      newExpireTime = oldRootRole.expires.plus(DEFAULT_EXPIRE_TIME)
      newRootRole = oldRootRole.copy(keys = newKeySet, roles = newRootRoleMap, version = oldRootRole.version + 1, newExpireTime)
      newRootSignature = TufCrypto.signPayload(newRootPrivKey, newRootRole).toClient(newRootPubKey.id)
      newRootClientOldSignature = TufCrypto.signPayload(oldRootPrivKey, newRootRole).toClient(oldRootPubKeyId)
      newSignedRoot = SignedPayload(Seq(newRootSignature, newRootClientOldSignature), newRootRole)
      _ = log.debug(s"pushing ${newSignedRoot.asJson.spaces2}")
      _ <- repoClient.pushSignedRoot(newSignedRoot)
      _ <- writeSignedRole(newSignedRoot).toFuture
    } yield newSignedRoot
  }

  def pushTargetsKey(reposerver: UserReposerverClient, keyName: KeyName): Future[TufKey] = {
    keyStorage.readPublicKey(keyName).toFuture.flatMap(reposerver.pushTargetsKey)
  }

  def authConfig(): Try[AuthConfig] =
    parseFile(repoPath.resolve("auth.json").toFile)
      .flatMap(_.as[AuthConfig])
      .toTry

  private def toByteArray(is: InputStream): Array[Byte] = {
    val baos = new ByteArrayOutputStream()
    Stream.continually(is.read).takeWhile(_ != -1).foreach(baos.write)
    baos.toByteArray
  }

  def export(targetKey: KeyName, exportPath: Path): Try[Unit] = {
    def copyEntries(src: ZipFile, dest: ZipOutputStream): Try[Unit] = Try {
      src.entries().foreach { zipEntry =>
        val is = src.getInputStream(zipEntry)

        if (zipEntry.getName == "treehub.json") {
          dest.putNextEntry(new ZipEntry("treehub.json"))
          readJsonFrom[Json](is).map { oldTreehubJson =>
            val newTreehubJson = oldTreehubJson.deepMerge(Json.obj("oauth2" -> authConfig().get.asJson))
            dest.write(newTreehubJson.spaces2.getBytes)
          }.get
        } else if (zipEntry.getName != zipTargetKeyName.publicKeyName && zipEntry.getName != zipTargetKeyName.privateKeyName) {
          // copy other files over
          dest.putNextEntry(zipEntry)
          dest.write(toByteArray(is))
        }

        dest.closeEntry()
      }
    }

    def copyKeyPair(pubKey: TufKey, privKey: TufPrivateKey, dest: ZipOutputStream): Try[Unit] = Try {
      dest.putNextEntry(new ZipEntry(zipTargetKeyName.publicKeyName))
      dest.write(pubKey.asJson.spaces2.getBytes())

      dest.putNextEntry(new ZipEntry(zipTargetKeyName.privateKeyName))
      dest.write(privKey.asJson.spaces2.getBytes())
    }

    Try(new ZipOutputStream(new FileOutputStream(exportPath.toFile))).flatMap { zipExportStream ⇒
      val sourceZip = new ZipFile(repoPath.resolve("credentials.zip").toFile)

      val t = for {
        (pubKey, privKey) <- keyStorage.readKeyPair(targetKey)
        _ ← copyEntries(sourceZip, zipExportStream)
        _ ← copyKeyPair(pubKey, privKey, zipExportStream)
      } yield ()

      Try(sourceZip.close())
      Try(zipExportStream.close())

      t
    }
  }
}
