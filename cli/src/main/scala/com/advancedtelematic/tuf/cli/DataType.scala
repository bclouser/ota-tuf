package com.advancedtelematic.tuf.cli

import java.net.URI

object DataType {
  case class KeyName(value: String) extends AnyVal

  case class RepoName(value: String) extends AnyVal

  case class AuthConfig(server: URI, client_id: String, client_secret: String)

  case class AuthPlusToken(value: String) extends AnyVal
}