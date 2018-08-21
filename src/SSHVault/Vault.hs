
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ScopedTypeVariables #-}

module SSHVault.Vault
    (
      encryptVault
    , decryptVault
    , getHosts
    , getUser
    , getUsers
    , getUsers2
    , updateUsers
    , updateVaultEntry
    , updateVault
    , toVaultHT
    , getSSHKeysHT
    , modifySSHKeysHT
    )
where

import qualified SSHVault.Vault.Config as Cfg
import           SSHVault.SBytes
import           SSHVault.Common

import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.Aeson as JSON
import           Data.Maybe (fromMaybe)
import qualified Data.HashTable.ST.Basic as HT
import           Control.Monad.ST

--import Control.Exception (SomeException, catch)



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

getUsers2 :: Cfg.Config -> AESMasterKey -> HostName -> UserName -> IO (Vault, User, [User])
getUsers2 cfg m h un = do
  (v :: Vault) <- decryptVault m (Cfg.file cfg)
  let users' = getUsers v h
  user' <- case getUser v h un of
      [u''] -> return u''
      _     -> error $ "missing user " ++ un
  return (v, user', users')


updateUsers :: [User] -> User -> [User]
updateUsers us u' = filter (\u'' -> user u'' /= un) us ++ [u'] where un = user u'

updateVaultEntry :: VaultEntry -> [User] -> VaultEntry
updateVaultEntry ve us = ve { users = us }

updateVault :: Vault -> VaultEntry -> Vault
updateVault v ve = v { vault = filter (\ve' -> host ve' /= hn) (vault v) ++ [ve] } where hn = host ve


decryptVault :: AESMasterKey -> String -> IO Vault
decryptVault key fn = do
  v <- B.readFile fn
    >>= decryptAES key
  case B64.decode (toBytes v) of
    Left  s' -> error s'
    Right s' -> return . fromMaybe (error "failed to JSON.decode in decryptVault") . JSON.decode $ toLUBytes s'

encryptVault :: AESMasterKey -> String -> Vault -> IO ()
encryptVault k fn v =
  encryptAES k (B64.encode . toBytes $ JSON.encode v)
  >>= \ c' -> B.writeFile fn (toBytes c')
  >> chmodF ("600" :: String) fn


toHostHT :: VaultEntry -> ST s (HostHT s)
toHostHT ve = do
  ht <- HT.new
  mapM_ (\u -> HT.insert ht (user u) (sshkeys u)) (getUsers (Vault { vault = [ve] }) (host ve))
  return ht

toVaultHT :: Vault -> ST s (VaultHT s)
toVaultHT v = do
  ht <- HT.new
  mapM_ (\ve -> do h <- toHostHT ve; HT.insert ht (host ve) h) (vault v)
  return ht

getSSHKeysHT :: VaultHT s -> HostName -> UserName -> ST s (Maybe [SSHKey])
getSSHKeysHT vst h un = do
  hst <- HT.lookup vst h
  case hst of
    Nothing   -> return Nothing
    Just hst' -> HT.lookup hst' un

modifySSHKeysHT :: VaultHT s -> HostName -> UserName -> ([SSHKey] -> [SSHKey]) -> ST s ()
modifySSHKeysHT vst h un f = do
  hst <- HT.lookup vst h
  case hst of
    Nothing   -> return ()
    Just hst' -> do
      kst <- HT.lookup hst' un
      case kst of
        Nothing   -> return ()
        Just kst' -> HT.insert hst' un (f kst')
