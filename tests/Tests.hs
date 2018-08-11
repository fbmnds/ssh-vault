
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE DeriveGeneric #-}

module Main where

import qualified SSHVault.Vault as V
import qualified SSHVault.Vault.Config as Cfg
--import SSHVault.Vault.Queue
import SSHVault.Workflows
import SSHVault.SBytes
import SSHVault.Common

import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteArray as BA

import Data.List (intercalate)
import Data.Maybe (fromMaybe)
import Data.Aeson
import GHC.Generics

import Test.QuickCheck

import Control.Exception (SomeException, catch)
import System.Exit (ExitCode(..))
import qualified Turtle as Tu
import qualified Turtle.Prelude as Tu
import Turtle.Format

instance Arbitrary B.ByteString where arbitrary = B.pack <$> arbitrary
instance CoArbitrary B.ByteString where coarbitrary = coarbitrary . B.unpack



data TestConfig =
  Config { host :: String
         , user :: String
         , mpw  :: String
    } deriving (Show, Generic, Eq)
instance FromJSON TestConfig
instance ToJSON TestConfig

-- | test0: check stabiltity of the vault record/JSON format

checkVaultJSON :: IO V.Vault
checkVaultJSON = do
  vsc' <- B.readFile "./tests/data/vault0.json"
  let vsc = toSBytes vsc'
  let v =
        fromMaybe
          (error "checkVaultJSON: failed to parse Vault decode $ encode\n")
          . decode $ toLUBytes vsc
  printf s "+++ OK, passed vault JSON decode test.\n"
  return v

getHosts :: V.Vault -> [String]
getHosts = fmap V.host . V.vault

testGetHost :: V.Vault -> IO ()
testGetHost v = case getHosts v of
  ["box1","box2","box3"] -> printf s "+++ OK, passed getHost test.\n"
  _                      -> error "--- ERR, failed getHost test.\n"

test0 :: IO ()
test0 = do
  v <- checkVaultJSON
  testGetHost v
  -- printf s . toText $ encodePretty vvf
  return ()


-- | test1 : roundtrip to/from disk for vault user update with new SSH key/passphrase

updateVault01 :: V.SSHKey -> V.Vault
updateVault01 s01' =
  let
    s01 = s01'
    s02 = V.SSHKey "YSpib3gxKioqKioq" "/home/a/.ssh/id_box1" "##################" "2018-08-05 17:58:39.67413695 UTC"
    u01 = V.User "root" [s01] "2018-08-05 17:58:39.67413695 UTC"
    u02 = V.User "a" [s02] "2018-08-05 17:58:39.67413695 UTC"
    h0  = V.HostData "" "" "" 22 "2018-08-05 17:58:39.67413695 UTC"
    ve0 = V.VaultEntry  "box1" h0 [u01,u02] "2018-08-05 17:58:39.67413695 UTC" in
  V.Vault [ve0]

genTestConfig :: IO Cfg.Config
genTestConfig = do
  vdir <- Tu.pwd
  return Cfg.Config {
        Cfg.dir      = toString (format fp vdir) ++ "/tests/data"
      , Cfg.file     = toString (format fp vdir) ++ "/tests/data/.vault"
      , Cfg.keystore = toString (format fp vdir) ++ "/tests/data/.vault/STORE"
      , Cfg.ttl      = 30
      }

test1 :: Cfg.Config -> IO ()
test1 dcfg = do
  h <- Tu.home
  let fn = toString (format fp h) ++ "/.ssh/vault" ++ ".NEW"
      vk = "0123456789" :: T.Text
      sk = [V.SSHKey "root*box1***"
                  "/root/.ssh/id_box1"
                  "##################"
                  "2018-08-05 17:58:39.67413695 UTC"]
      u' = V.User "root" sk "2018-08-05 17:58:39.67413695 UTC"

  s' <- genSSHKey dcfg (toSBytes (""::String)) "root" u'
  let v1 = updateVault01 $ V.SSHKey (V.phrase64 s') (V.key_file s') "##################" "2018-08-05 17:58:39.67413695 UTC"
  printf s "+++ OK, passed genSSHKey test.\n"

  V.encryptVault (toSBytes $ genAESKey vk) fn v1
  printf s "[*] encryptVault\n"
  v2 <- V.decryptVault (toSBytes $ genAESKey vk) fn
  if v1 == v2 then printf s "+++ OK, passed decryptVault test.\n" else
    printf s "-- ERR, failed decryptVault test.\n"



writeSSHKey :: BA.ScrubbedBytes -> V.SSHKey -> IO ExitCode
writeSSHKey m sk = catch (do
  putStrLn $ "LOG: writeSSHKey sk " ++ (show sk)
  let priv = V.key_file sk
      pub  = priv ++ ".pub"
  ph <- case B64.decode . toBytes $ V.phrase64 sk of
    Left _   -> error "failed to b64decode SSH key passphrase"
    Right s0 -> do
        ph' <- decryptAES m s0
        return $ toString ph'
  B.writeFile priv (toBytes $ V.key_content sk)
  chmodFile ("600" :: String) (priv :: String)
  procEC $ "ssh-keygen -f " ++ priv ++ " -y -P " ++ ph ++ " > " ++ pub
  chmodFile ("644" :: String) (pub :: String)
  return ExitSuccess
  )
  (\(e' :: SomeException) -> do
    putStrLn $ "LOG: could not write SSH key:\n" ++ show e'
    return (ExitFailure 1))


--writeUserSSHKeys :: BA.ScrubbedBytes -> V.Vault -> V.HostName -> V.UserName -> IO ([FilePath],[FilePath])
writeUserSSHKeys m v h un = do
  let sks = concat . fmap V.sshkeys $ V.getUser v h un
  mapM_ (\ sk -> do
            r <- writeSSHKey m sk
            case r of
              ExitSuccess -> putStrLn "ok"
              _           -> putStrLn "fail") sks
  --putStrLn  ("LOG : # SSH keys = " ++ (show $ length x'))
  {-
  r0 <- foldl (\ acc sk -> do
    r <- writeSSHKey m sk
    case r of
      ExitSuccess -> do
        f <- fst acc
        s <- snd acc
        return (f ++ [V.key_file sk],s)
      (ExitFailure _)-> do
        f <- fst acc
        s <- snd acc
        return (f,s ++ [V.key_file sk])) IO (IO [],IO []) sks
  return r0
-}

test2 :: IO ()
test2 = do
  cfg <- Cfg.genDefaultConfig
  tcfg' <- B.readFile $ Cfg.dir cfg ++ "/test.json"
  (tcfg :: TestConfig) <- return
    . fromMaybe (error "failed to JSON.decode in test2")
    . decode $ toLUBytes tcfg'
  let un   = user tcfg
      h    = host tcfg
      m    = genAESKey . toText $ mpw  tcfg
      cmd  =  "ssh " ++ un ++ "@" ++ h ++ " 'cat ~/.ssh/authorized_keys'"
  (v :: V.Vault) <- V.decryptVault m (Cfg.file cfg)
  _ <- case V.getUser v h un of
      [u''] -> return u''
      []    -> error $ "missing user " ++ un
      _     -> error "vault inconsistent"
  writeUserSSHKeys m v h un
  --putStrLn . show $ length x'
  {-
  sshAdd (cfg { Cfg.ttl = 1 }) m h un
  r <- procEC cmd
  case r of
      (ExitFailure _, o', e') -> do
        putStrLn $ "LOG :" ++ show e'
        putStrLn $ "LOG :" ++ show o'
        error "failed to ssh"
      (ExitSuccess  , o', e') -> do
        putStrLn $ "LOG :" ++ show e'
        putStrLn o'
        --return o'
-}


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
  where t'  = SSHVault.SBytes.toText t
        t'' = toBytes t



main :: IO ()
main = do
  test2
  test0
  --dcfg <- genTestConfig
  --test1 dcfg
  quickCheck prop_scrubbedbytes
  --shellD $ "rm " ++ Cfg.keystore dcfg ++ "/*"
