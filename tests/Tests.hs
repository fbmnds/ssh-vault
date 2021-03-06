
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE DeriveGeneric #-}

module Main where


import SSHVault.SBytes
import SSHVault.Vault
import qualified SSHVault.Vault.Config as Cfg
import SSHVault.Workflows
import SSHVault.Common

import qualified Data.ByteString as B
--import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteArray as BA

-- import Data.Text (splitOn)
-- import Data.List (intercalate)
import Data.Maybe (fromMaybe)
import Data.Aeson as JSON
import Data.Aeson.Encode.Pretty (encodePretty)
import GHC.Generics

import Test.QuickCheck

-- import Control.Concurrent (threadDelay)
import Control.Exception
  (SomeException
  , catch
--  , bracket
  )
import Control.Monad
--import System.Exit (ExitCode(..))
import System.Directory

{-
import Foreign
import Foreign.C.Types
import Foreign.C.String
-}

instance Arbitrary B.ByteString where arbitrary = B.pack <$> arbitrary
instance CoArbitrary B.ByteString where coarbitrary = coarbitrary . B.unpack



data TestConfig =
  Config { thost :: String
         , tuser :: String
         , mpw   :: String
    } deriving (Show, Generic, Eq)
instance FromJSON TestConfig
instance ToJSON TestConfig

-- | test0: check vault deserialization (unencrypted)

test0 :: IO ()
test0 = catch (do
  v <- checkVaultJSON
  testGetHost v
  putStrLn "\n+++ OK, passed test0: check vault deserialization (unencrypted)."
  )(\ (e' :: SomeException) -> error $ "\n--- ERR, failed test0: check vault deserialization (unencrypted).\n" ++ show e')
  where
    checkVaultJSON :: IO Vault
    checkVaultJSON = do
      vsc' <- B.readFile "./tests/data/vault0.json"
      let vsc = toLUBytes vsc'
      return . fromMaybe (error "checkVaultJSON: failed to parse Vault decode $ encode\n") $ JSON.decode vsc
    testGetHost :: Vault -> IO ()
    testGetHost v = case getHosts v of
      ["box1","box2","box3"] -> putStrLn "+++ OK, passed getHost test."
      _                      -> error "--- ERR, failed getHost test.\n"




-- | test1 : roundtrip to/from disk for vault user update with new SSH key/passphrase

test1 :: Cfg.Config -> IO ()
test1 dcfg = do
  let debug = False
  h <- getHomeDirectory
  let fn = h ++ "/.ssh/vault" ++ ".NEW"
      m = genAESKey $ toMasterKey "0123456789"
      sk = [SSHKey
              (toKeyPhrase64 "root*box1***")
              "/root/.ssh/id_box1"
              "##################"
              "##################"
              "2018-08-05 17:58:39.67413695 UTC"]
      u' = User "root" sk ["pub1","pub2"] "2018-08-05 17:58:39.67413695 UTC"

  s' <- genSSHKeyU dcfg m "root" u'

  let v1 = updateVault01 $
        SSHKey
          (phrase64 s')
          (key_file s')
          "##################"
          "##################"
          "2018-08-05 17:58:39.67413695 UTC"

  putStrLn "[+] passed genSSHKeyU and vault update."

  encryptVault m fn v1
  putStrLn "[*] encryptVault"
  (v2 :: Vault) <- decryptVault m fn
  putStrLn "[*] decryptVault"
  when debug . putStrLn . toString  $ encodePretty v1
  when debug . putStrLn . toString  $ encodePretty v2
  if v1 == v2 then putStrLn "+++ OK, passed test1 : roundtrip to/from disk for vault user update."
  else             putStrLn "--- ERR, failed test1 : roundtrip to/from disk for vault user update."
  where
    updateVault01 :: SSHKey -> Vault
    updateVault01 s01' =
      let
        s01 = s01'
        s02 = SSHKey
                (toKeyPhrase64 "YSpib3gxKioqKioq")
                "/home/a/.ssh/id_box1"
                "##################"
                "##################"
                "2018-08-05 17:58:39.67413695 UTC"
        u01 = User "root" [s01] [] "2018-08-05 17:58:39.67413695 UTC"
        u02 = User "a" [s02] ["pub1","pub2"] "2018-08-05 17:58:39.67413695 UTC"
        h0  = HostData "" "" "" 22 "2018-08-05 17:58:39.67413695 UTC"
        ve0 = VaultEntry  "box1" h0 [u01,u02] "2018-08-05 17:58:39.67413695 UTC" in
      Vault [ve0]



-- test2 : confirm SSH access via FFI call to ssh-add

test2 :: IO ()
test2 = do
  let debug = False
  (cfg,m,h,un) <- initTests
  (v :: Vault) <- decryptVault m (Cfg.file cfg)
  when debug . putStrLn . toString  $ encodePretty v
  _ <- case getUser v h un of
      [u''] -> return u''
      []    -> error $ "missing user " ++ un
      _     -> error "vault inconsistent"
  r <- confirmSSHAccess cfg m h un
  case r of
    "Access confirmed" -> do putStrLn "+++ OK, test2 : access confirmed"; return ()
    _                  -> error "--- ERR, test2 : access failed"



-- test3 : test key rotation

test3 :: IO ()
test3 = do
  (cfg,m,h,un) <- initTests
  rotateUserSSHKey cfg m h un
  r <- confirmSSHAccess  cfg m h un
  if r == "Access failed" then error "--- ERR, test3 : SSH key rotation failed"
  else putStrLn "+++, OK test3 : successful SSH key rotation"



-- test4 : test purging keys

test4 :: IO ()
test4 = do
  (cfg,m,h,un) <- initTests
  purgeUserSSHKeys cfg m h un
  r <- confirmSSHAccess  cfg m h un
  if r == "Access failed" then error "--- ERR, test4 : purging SSH keys failed"
  else putStrLn "+++, OK test4 : successful purging SSH keys"




-- test5 : change vault password

test5 :: IO ()
test5 = do
  (cfg,m,_,_) <- initTests
  let m2 = genAESKey $ toMasterKey "abc0123456789"
  changeAESMasterKey cfg m m2



-- | property check on string conversions (depricated)

prop_scrubbedbytes :: B.ByteString -> Property
prop_scrubbedbytes t =
  True
    ==>  toSBytes t
    `BA.eq` toBytes (toSBytes t)
    ==   toBytes t
    `BA.eq` toBytes (toSBytes t)
    &&   toSBytes t'
    `BA.eq` toBytes (toSBytes t')
    ==   toBytes t'
    `BA.eq` toBytes (toSBytes t')
    &&   toSBytes t''
    `BA.eq` toSBytes (toLUBytes t'')
    ==   toBytes t''
    `BA.eq` toBytes (toLUBytes t'')
  where t'  = toText t
        t'' = toBytes t


-- | test setup

genTestConfig :: IO Cfg.Config
genTestConfig = do
  vdir <- getCurrentDirectory
  return Cfg.Config {
        Cfg.dir      = vdir ++ "/tests/data"
      , Cfg.file     = vdir ++ "/tests/data/.vault"
      , Cfg.keystore = vdir ++ "/tests/data/.vault/STORE"
      , Cfg.ttl      = 1
      }

initTests :: IO (Cfg.Config, AESMasterKey, HostName, UserName)
initTests =  do
  cfg <- Cfg.genDefaultConfig
  procD "cp" [Cfg.file cfg, Cfg.file cfg ++ ".1"]
  tcfg' <- B.readFile $ Cfg.dir cfg ++ "/test.json"
  (tcfg :: TestConfig) <- return
    . fromMaybe (error "failed to JSON.decode in test2")
    . decode $ toLUBytes tcfg'
  let un   = tuser tcfg
      h    = thost tcfg
      m    = genAESKey . toMasterKey $ mpw  tcfg
  return (cfg,m,h,un)


 -- | run tests

main :: IO ()
main = do
  test0
  dcfg <- genTestConfig
  test1 dcfg
  shellD $ "rm " ++ Cfg.keystore dcfg ++ "/*"
  test2
  --test3
  --test4
  test5
  quickCheck prop_scrubbedbytes
