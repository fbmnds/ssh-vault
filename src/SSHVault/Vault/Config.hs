{-# LANGUAGE DeriveGeneric #-}
module SSHVault.Vault.Config
  ( Config (..)
  , genDefaultConfig
  )
  where

import           SSHVault.SBytes

import qualified Data.Aeson as JSON
import           GHC.Generics

import qualified Turtle as Tu
import           Turtle.Format


data Config =
  Config { dir      :: String
         , file     :: String
         , keystore :: String
         , ttl      :: Int
    } deriving (Show, Generic, Eq)
instance JSON.FromJSON Config
instance JSON.ToJSON Config


-- type Config = (BA.ScrubbedBytes, Tu.FilePath, String)

genDefaultConfig :: IO Config
genDefaultConfig = do
  hdir <- Tu.home
  return Config {
        dir = toString (format fp hdir) ++ "/.vault"
      , file = toString (format fp hdir) ++ "/.vault/vault"
      , keystore = toString (format fp hdir) ++ "/.vault/STORE"
      , ttl = 90
      }
