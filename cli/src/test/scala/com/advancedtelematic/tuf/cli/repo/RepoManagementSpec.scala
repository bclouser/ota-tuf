package com.advancedtelematic.tuf.cli.repo

import java.nio.file.{Files, Path, Paths}
import io.circe.jawn._
import com.advancedtelematic.libtuf.data.TufDataType.{EdKeyType, EdTufKey, EdTufPrivateKey, TufKey, TufPrivateKey}
import com.advancedtelematic.tuf.cli.DataType.{AuthConfig, KeyName, RepoName}
import com.advancedtelematic.tuf.cli.{CliSpec, RandomNames}
import cats.syntax.either._
import com.advancedtelematic.tuf.cli.CliCodecs.authConfigDecoder
import com.advancedtelematic.libtuf.data.TufCodecs._

import scala.util.{Success, Try}

class RepoManagementSpec extends CliSpec {

  lazy val treehubCredentials: Path = Paths.get(this.getClass.getResource("/treehub.json").toURI)
  lazy val credentialsZip: Path = Paths.get(this.getClass.getResource("/credentials.zip").toURI)
  lazy val credentialsZipNoTargets: Path = Paths.get(this.getClass.getResource("/credentials_notargets.zip").toURI)

  import scala.concurrent.ExecutionContext.Implicits.global

  def randomName = RepoName(RandomNames() + "-repo")

  def randomRepoPath = Files.createTempDirectory("tuf-repo")

  test("can read auth config for an initialized repo") {
    val repoT = RepoManagement.initialize(randomName, randomRepoPath, treehubCredentials)

    repoT shouldBe a[Success[_]]

    repoT.get.authConfig().get shouldBe a[AuthConfig]
  }

  test("can initialize repo from ZIP file") {
    val repoT = RepoManagement.initialize(randomName, randomRepoPath, credentialsZip)
    repoT shouldBe a[Success[_]]
  }

  test("can initialize repo from ZIP file without targets keys") {
    val repoT = RepoManagement.initialize(randomName, randomRepoPath, credentialsZipNoTargets)
    repoT shouldBe a[Success[_]]
    repoT.get.repoPath.resolve("keys/targets.pub").toFile.exists() shouldBe false
  }

  test("reads targets keys from credentials.zip if present") {
    val repoT = RepoManagement.initialize(randomName, randomRepoPath, credentialsZip)
    repoT shouldBe a[Success[_]]

    val repo = repoT.get

    repo.authConfig().get shouldBe a[AuthConfig]
    parseFile(repo.repoPath.resolve("keys/targets.pub").toFile).flatMap(_.as[TufKey]).valueOr(throw _) shouldBe a[EdTufKey]
    parseFile(repo.repoPath.resolve("keys/targets.sec").toFile).flatMap(_.as[TufPrivateKey]).valueOr(throw _) shouldBe a[EdTufPrivateKey]
  }


  test("can export zip file") {
    val repo = RepoManagement.initialize(randomName, randomRepoPath, credentialsZip).get

    // overwrite with different auth values:
    RepoManagement.initialize(repo.name, repo.repoPath, treehubCredentials)

    repo.genKeys(KeyName("default-key"), EdKeyType, 256)

    val tempPath = Paths.get(s"/tmp/tuf-repo-spec-export-${RandomNames()}.zip")

    RepoManagement.export(repo, KeyName("default-key"), tempPath) shouldBe Try(())

    // test the exported zip file by creating another repo from it:
    val repoFromExported = RepoManagement.initialize(randomName, randomRepoPath, tempPath).get
    val credJson = parseFile(repoFromExported.repoPath.resolve("auth.json").toFile)
    val oauth2Val = credJson.right.get.as[AuthConfig]
    oauth2Val.right.get.client_id shouldBe "fake-client-id"
  }
}
