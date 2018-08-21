{-# LANGUAGE DeriveGeneric #-}
module SSHVault.Vault.Config
  ( Config (..)
  , genDefaultConfig
  )
  where


import qualified Data.Aeson as JSON
import           GHC.Generics

import System.Directory


data Config =
  Config { dir      :: String
         , file     :: String
         , keystore :: String
         , ttl      :: Int
    } deriving (Show, Generic, Eq)
instance JSON.FromJSON Config
instance JSON.ToJSON Config



genDefaultConfig :: IO Config
genDefaultConfig = do
  hdir <- getHomeDirectory
  return Config {
        dir = hdir ++ "/.vault"
      , file = hdir ++ "/.vault/vault"
      , keystore = hdir ++ "/.vault/STORE"
      , ttl = 90
      }
