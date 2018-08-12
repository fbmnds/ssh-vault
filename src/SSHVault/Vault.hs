
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ScopedTypeVariables #-}
--{-# LANGUAGE DeriveGeneric #-}

module SSHVault.Vault
    (
      encryptVault
    , decryptVault
    , getHosts
    , getUser
    , getUsers
    , updateUsers
    , updateVaultEntry
    , updateVault
    )
where

import           SSHVault.SBytes
import           SSHVault.Common

import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.Aeson as JSON
import           Data.Maybe (fromMaybe)



getHosts :: Vault -> [String]
getHosts = fmap host . vault

getUser :: Vault -> HostName -> UserName -> [User]
getUser v h un = case filter (\ uvh -> user uvh == un) . concatMap users $ filter (\ ve -> host ve == h) (vault v) of
  []   -> []
  [u'] -> [u']
  _    -> error $ "vault inconsistent: multiple entries for user " ++ un

getUsers :: Vault -> HostName -> [User]
getUsers v h = case filter (\ ve -> host ve == h) (vault v) of
  []   -> []
  [ve] -> users ve
  _    -> error $ "vault inconsistent: multiple entries for host " ++ h

updateUsers :: [User] -> User -> [User]
updateUsers us u' = filter (\u'' -> user u'' /= un) us ++ [u'] where un = user u'

updateVaultEntry :: VaultEntry -> [User] -> VaultEntry
updateVaultEntry ve us = ve { users = us }

updateVault :: Vault -> VaultEntry -> Vault
updateVault v ve = v { vault = filter (\ve' -> host ve' /= hn) (vault v) ++ [ve] } where hn = host ve


decryptVault :: JSON.FromJSON a => AESMasterKey -> String -> IO a
decryptVault key fn = do
  v <- B.readFile fn
    >>= decryptAES key
  case B64.decode (toBytes v) of
    Left s' -> error s'
    Right s' -> return . fromMaybe (error "failed to JSON.decode in decryptVault") . JSON.decode $ toLUBytes s'

encryptVault :: AESMasterKey -> String -> Vault -> IO ()
encryptVault k fn v =
  encryptAES k (B64.encode . toBytes $ JSON.encode v)
  >>= \ c' -> B.writeFile fn (toBytes c')
  >> chmodFile ("600" :: String) fn
