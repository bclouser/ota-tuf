package com.advancedtelematic.tuf.reposerver.delegations

import cats.data.Validated.{Invalid, Valid}
import cats.data.ValidatedNel
import com.advancedtelematic.libats.data.RefinedUtils._
import com.advancedtelematic.libtuf.crypt.TufCrypto
import com.advancedtelematic.libtuf.data.ClientCodecs._
import com.advancedtelematic.libtuf.data.ClientDataType.{DelegatedRoleName, Delegation, MetaItem, MetaPath, TargetsRole, ValidMetaPath}
import com.advancedtelematic.libtuf.data.TufDataType.{JsonSignedPayload, RepoId, SignedPayload}
import com.advancedtelematic.libtuf_server.crypto.Sha256Digest
import com.advancedtelematic.libtuf_server.repo.server.DataType.SignedRole
import com.advancedtelematic.libtuf_server.repo.server.SignedRoleGeneration
import com.advancedtelematic.tuf.reposerver.db.{DelegationRepositorySupport, SignedRoleRepositorySupport}
import com.advancedtelematic.tuf.reposerver.http._
import slick.jdbc.MySQLProfile.api._

import scala.async.Async._
import scala.concurrent.{ExecutionContext, Future}
import scala.util.Try

class SignedRoleDelegationsFind()(implicit val db: Database, val ec: ExecutionContext) extends DelegationRepositorySupport {
  import cats.implicits._
  import com.advancedtelematic.libtuf.crypt.CanonicalJson._
  import com.advancedtelematic.libtuf.data.TufCodecs._
  import io.circe.syntax._

  def findSignedTargetRoleDelegations(repoId: RepoId, targetRole: SignedRole[TargetsRole]): Future[Map[MetaPath, MetaItem]] = {
    println("BEN SAYS: Inside SignedRoleDelegationsFind.findSignedTargetRoleDelegations()")
    val delegatedRoleNames = targetRole.role.delegations.map(_.roles.map(_.name)).getOrElse(List.empty)
    println("BEN SAYS: delegatedRoleNames found from the targets role: " + delegatedRoleNames)
    val delegationsF =
      delegatedRoleNames
        .map { name => 
          val foundDelegation = delegationsRepo.find(repoId, name).map((name, _)) 
          println("BEN SAYS: (.map) Found delegation ("+name.value+") in database")
          foundDelegation}
        .sequence
        .recover { case Errors.DelegationNotFound => 
          println("BEN SAYS: (.recover) Failed to find delegation in delegationsRepo db")
        List.empty }
    for {
      delegations <- delegationsF
      delegationsAsMetaItems <- delegations.map { case (name, d) =>
        println("BEN SAYS: trying to place name.value= " + name.value)
        Future.fromTry { (name.value + ".json").refineTry[ValidMetaPath].product(asMetaItem(d.content)) }
      }.sequence
    } yield delegationsAsMetaItems.toMap
  }

  private def asMetaItem(content: JsonSignedPayload): Try[MetaItem] = {
    val canonicalJson = content.asJson.canonical
    val checksum = Sha256Digest.digest(canonicalJson.getBytes)
    val hashes = Map(checksum.method -> checksum.hash)
    val versionT = content.signed.hcursor.downField("version").as[Int].toTry

    versionT.map { version => MetaItem(hashes, canonicalJson.length, version) }
  }
}


class DelegationsManagement()(implicit val db: Database, val ec: ExecutionContext)
                                                  extends DelegationRepositorySupport with SignedRoleRepositorySupport {
  def create(repoId: RepoId, roleName: DelegatedRoleName, delegationMetadata: SignedPayload[TargetsRole])
            (implicit signedRoleGeneration: SignedRoleGeneration): Future[Unit] = async {
              println("BEN SAYS: Inside DelegationsManagement.create()")
    val targetsRole = await(signedRoleRepository.find[TargetsRole](repoId)).role
    val delegation = findDelegationMetadataByName(targetsRole, roleName)

    validateDelegationMetadataSignatures(targetsRole, delegation, delegationMetadata) match {
      case Valid(_) =>
        println("BEN SAYS: Delegation signatures are valid. roleName= " + roleName )
        await(delegationsRepo.persist(repoId, roleName, delegationMetadata.asJsonSignedPayload))
        val snapshots, timestamps = await(signedRoleGeneration.regenerateSnapshots(repoId))
        println("BEN SAYS: Snapshots returned from regenerateSnapshots(). Snapshotsjson: " + snapshots)
      case Invalid(err) =>
        throw Errors.PayloadSignatureInvalid(err)
    }
  }

  def find(repoId: RepoId, roleName: DelegatedRoleName): Future[JsonSignedPayload] =
    delegationsRepo.find(repoId, roleName).map(_.content)

  private def findDelegationMetadataByName(targetsRole: TargetsRole, delegatedRoleName: DelegatedRoleName): Delegation = {
    targetsRole.delegations.flatMap(_.roles.find(_.name == delegatedRoleName)).getOrElse(throw Errors.DelegationNotDefined)
  }
  private def validateDelegationMetadataSignatures(targetsRole: TargetsRole,
                                                   delegation: Delegation,
                                                   delegationMetadata: SignedPayload[TargetsRole]): ValidatedNel[String, SignedPayload[TargetsRole]] = {
    val publicKeys = targetsRole.delegations.map(_.keys).getOrElse(Map.empty).filterKeys(delegation.keyids.contains)
    TufCrypto.payloadSignatureIsValid(publicKeys, delegation.threshold, delegationMetadata)
  }
}
