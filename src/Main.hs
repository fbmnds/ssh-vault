
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
--{-# LANGUAGE DeriveGeneric #-}
module Main where

{-
import SshVault.Workflows (ssh)
import SshVault.Vault 
    ( Vault (..)
    , VaultEntry (..)
    , Secrets (..)
    , getVaultFile'
    , putVaultFile'
    , getVaultFile
    , putVaultFile
    , encryptVault
    , decryptVault
    )
import SshVault.Common (getKeyPhrase)

import Data.ByteString.Lazy (ByteString)
import Data.ByteString.Lazy.Char8 (unpack)
import Data.Maybe (fromMaybe)
import Data.Aeson
import Data.Aeson.Types 
import Data.Aeson.Encode.Pretty
import Data.Text(Text, pack)

import GHC.Generics
-}

import Turtle
    ( 
      ExitCode
    , printf
    , fromString
    , liftIO
    , readline
    , view
    )
import Turtle.Format
import Turtle.Prelude 
    (
      shell
--    , input
--    , stdout
    )
--import Turtle.Line (lineToText)


nl :: IO ()
nl = printf s "\n"


done :: IO ExitCode
done = shell "" ""


main :: IO ExitCode
main = do
  nl
  done


 