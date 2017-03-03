package com.advancedtelematic.tuf.keyserver.db

import java.security.PublicKey

import akka.http.scaladsl.model.Uri
import com.advancedtelematic.libtuf.data.TufDataType.KeyType.KeyType
import com.advancedtelematic.libtuf.data.TufDataType.{Checksum, KeyId, RepoId}
import com.advancedtelematic.libtuf.data.TufDataType.RoleType.RoleType
import com.advancedtelematic.tuf.keyserver.data.KeyServerDataType._
import com.advancedtelematic.tuf.keyserver.data.KeyServerDataType.KeyGenRequestStatus.KeyGenRequestStatus
import slick.driver.MySQLDriver.api._
import io.circe.Json

object Schema {
  import com.advancedtelematic.libats.codecs.SlickRefined._
  import com.advancedtelematic.libtuf.data.SlickPublicKeyMapper._
  import com.advancedtelematic.libtuf.data.SlickUriMapper._
  import com.advancedtelematic.libtuf.data.SlickCirceMapper._

  class KeyGenRequestTable(tag: Tag) extends Table[KeyGenRequest](tag, "key_gen_requests") {
    def id = column[KeyGenId]("id", O.PrimaryKey)
    def repoId = column[RepoId]("repo_id")
    def status = column[KeyGenRequestStatus]("status")
    def roleType = column[RoleType]("role_type")
    def keySize = column[Int]("key_size")
    def threshold = column[Int]("threshold")

    def uniqueRepoIdRoleTypeIdx = index("key_gen_requests_unique_idx", (repoId, roleType), unique = true)

    override def * = (id, repoId, status, roleType, keySize, threshold) <> ((KeyGenRequest.apply _).tupled, KeyGenRequest.unapply)
  }

  protected [db] val keyGenRequests = TableQuery[KeyGenRequestTable]

  class KeyTable(tag: Tag) extends Table[Key](tag, "keys") {
    def id = column[KeyId]("key_id", O.PrimaryKey)
    def roleId = column[RoleId]("role_id")
    def keyType = column[KeyType]("key_type")
    def publicKey = column[PublicKey]("public_key")

    def roleFk = foreignKey("keys_role_fk", roleId, roles)(_.id)

    override def * = (id, roleId, keyType, publicKey) <> ((Key.apply _).tupled, Key.unapply)
  }

  protected [db] val keys = TableQuery[KeyTable]

  class RoleTable(tag: Tag) extends Table[Role](tag, "roles") {
    def id = column[RoleId]("role_id", O.PrimaryKey)
    def repoId = column[RepoId]("repo_id")
    def roleType = column[RoleType]("role_type")
    def threshold = column[Int]("threshold")

    def uniqueRepoIdRoleTypeIdx = index("roles_unique_idx", (repoId, roleType), unique = true)

    override def * = (id, repoId, roleType, threshold) <> ((Role.apply _).tupled, Role.unapply)
  }

  protected [db] val roles = TableQuery[RoleTable]
}