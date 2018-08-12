
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE DeriveGeneric #-}

module Main where


import qualified SSHVault.SBytes as Ty
import qualified SSHVault.Vault as V
import qualified SSHVault.Vault.Config as Cfg
import SSHVault.Workflows
import SSHVault.Common

import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteArray as BA
import Data.Set
import Data.Text (Text, splitOn)
import Data.Maybe (fromMaybe)
import Data.Aeson as JSON
-- import Data.Aeson.Encode.Pretty (encodePretty)
import GHC.Generics

import Test.QuickCheck

import Control.Exception (SomeException, catch)
import Control.Monad
import System.Exit (ExitCode(..))
import qualified Turtle as Tu
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

-- | test0: check vault deserialization (unencrypted)

test0 :: IO ()
test0 = catch (do
  v <- checkVaultJSON
  testGetHost v
  putStrLn "\n+++ OK, passed test0: check vault deserialization (unencrypted)."
  )(\ (e' :: SomeException) -> error $ "\n--- ERR, failed test0: check vault deserialization (unencrypted).\n" ++ show e')
  where
    checkVaultJSON :: IO Ty.Vault
    checkVaultJSON = do
      vsc' <- B.readFile "./tests/data/vault0.json"
      let vsc = Ty.toLUBytes vsc'
      return . fromMaybe (error "checkVaultJSON: failed to parse Vault decode $ encode\n") $ JSON.decode vsc
    testGetHost :: Ty.Vault -> IO ()
    testGetHost v = case V.getHosts v of
      ["box1","box2","box3"] -> putStrLn "+++ OK, passed getHost test."
      _                      -> error "--- ERR, failed getHost test.\n"




-- | test1 : roundtrip to/from disk for vault user update with new SSH key/passphrase

test1 :: Cfg.Config -> IO ()
test1 dcfg = do
  h <- Tu.home
  let fn = Ty.toString (format fp h) ++ "/.ssh/vault" ++ ".NEW"
      m = genAESKey $ Ty.toMasterKey "0123456789"
      sk = [Ty.SSHKey
              (Ty.toKeyPhrase64 "root*box1***")
              "/root/.ssh/id_box1"
              "##################"
              "##################"
              "2018-08-05 17:58:39.67413695 UTC"]
      u' = Ty.User "root" sk "2018-08-05 17:58:39.67413695 UTC"

  s' <- genSSHKeyU dcfg m "root" u'

  let v1 = updateVault01 $
        Ty.SSHKey
          (Ty.phrase64 s')
          (Ty.key_file s')
          "##################"
          "##################"
          "2018-08-05 17:58:39.67413695 UTC"

  putStrLn "[+] passed genSSHKeyU and vault update."

  V.encryptVault m fn v1
  putStrLn "[*] encryptVault"
  (v2 :: Ty.Vault) <- V.decryptVault m fn
  putStrLn "[*] decryptVault"
  -- putStrLn . Ty.toString  $ encodePretty v1
  -- putStrLn . Ty.toString  $ encodePretty v2
  if v1 == v2 then putStrLn "+++ OK, passed test1 : roundtrip to/from disk for vault user update."
  else             putStrLn "--- ERR, failed test1 : roundtrip to/from disk for vault user update."
  where
    updateVault01 :: Ty.SSHKey -> Ty.Vault
    updateVault01 s01' =
      let
        s01 = s01'
        s02 = Ty.SSHKey
                (Ty.toKeyPhrase64 "YSpib3gxKioqKioq")
                "/home/a/.ssh/id_box1"
                "##################"
                "##################"
                "2018-08-05 17:58:39.67413695 UTC"
        u01 = Ty.User "root" [s01] "2018-08-05 17:58:39.67413695 UTC"
        u02 = Ty.User "a" [s02] "2018-08-05 17:58:39.67413695 UTC"
        h0  = Ty.HostData "" "" "" 22 "2018-08-05 17:58:39.67413695 UTC"
        ve0 = Ty.VaultEntry  "box1" h0 [u01,u02] "2018-08-05 17:58:39.67413695 UTC" in
      Ty.Vault [ve0]



-- develop key synchronization

writeSSHKey :: Ty.AESMasterKey -> Ty.SSHKey -> IO ExitCode
writeSSHKey m sk = catch (do
  let priv = Ty.key_file sk
      pub  = priv ++ ".pub"
  ph <- case B64.decode . Ty.toBytes $ Ty.phrase64 sk of
    Left _   -> error "failed to b64decode SSH key passphrase"
    Right s0 -> do
        ph' <- decryptAES m s0
        return $ Ty.toString ph'
  B.writeFile priv (Ty.toBytes $ Ty.key_priv sk)
  chmodFile ("600" :: String) (priv :: String)
  _ <- procEC $ "ssh-keygen -f " ++ priv ++ " -y -P " ++ ph ++ " > " ++ pub
  chmodFile ("644" :: String) (pub :: String)
  return ExitSuccess
  )
  (\(e' :: SomeException) -> do
    putStrLn $ "LOG: could not write SSH key:" ++ Ty.key_file sk ++ "(.pub)\n" ++ show e'
    return (ExitFailure 1))


writeUserSSHKeys :: Ty.AESMasterKey -> Ty.Vault -> Ty.HostName -> Ty.UserName -> IO ([Ty.SSHKey], [String], [String])
writeUserSSHKeys m v h un = do
  let sks = concatMap Ty.sshkeys $ V.getUser v h un
  rs <- mapM (\sk -> do ec <-  writeSSHKey m sk; return (Ty.key_file sk,ec)) sks
  rs' <- foldM (\ acc (fn,ec) -> case ec of
    ExitSuccess -> return (fst acc ++ [fn], snd acc)
    _           -> return (fst acc, snd acc ++ [fn])) ([],[]) rs
  mapM_ (\ err -> putStrLn $ "LOG: could not write " ++ err) (snd rs')
  return (sks, fst rs', snd rs')


readPubSSHFilesFromVault :: Cfg.Config -> Ty.AESMasterKey -> Ty.HostName -> Ty.UserName -> IO [String]
readPubSSHFilesFromVault cfg m h un = do
  (v :: Ty.Vault) <- V.decryptVault m (Cfg.file cfg)
  u' <- case V.getUser v h un of
      [u''] -> return u''
      []    -> error $ "missing user " ++ un
      _     -> error "vault inconsistent"
  return $ fmap Ty.key_pub (Ty.sshkeys u')


getAuthorizedKeys :: Cfg.Config -> Ty.AESMasterKey -> Ty.HostName -> Ty.UserName -> IO [Data.Text.Text]
getAuthorizedKeys cfg m h un = do
  let cmd  = "ssh " ++ un ++ "@" ++ h ++ " 'cat ~/.ssh/authorized_keys'"
  sshAdd (cfg { Cfg.ttl = 1 }) m h un
  r <- procEC cmd
  a_k <- case r of
      (ExitFailure _, o', e') -> do
        putStrLn $ "LOG :" ++ show e'
        unless (Prelude.null o') $ putStrLn $ "LOG :" ++ show o'
        error "failed to retrieve authorized_keys"
      (ExitSuccess  , o', e') -> do
        unless (Prelude.null e') $ putStrLn $ "LOG :" ++ show e'
        return o'
  return $ splitOn (Ty.toText "\n") (Ty.toText a_k)

-- test2 : test key synchronization WIP

test2 :: IO ()
test2 = do
  cfg <- Cfg.genDefaultConfig
  tcfg' <- B.readFile $ Cfg.dir cfg ++ "/test.json"
  (tcfg :: TestConfig) <- return
    . fromMaybe (error "failed to JSON.decode in test2")
    . decode $ Ty.toLUBytes tcfg'
  let un   = user tcfg
      h    = host tcfg
      m    = genAESKey . Ty.toMasterKey $ mpw  tcfg

  (v :: Ty.Vault) <- V.decryptVault m (Cfg.file cfg)
  _ <- case V.getUser v h un of
      [u''] -> return u''
      []    -> error $ "missing user " ++ un
      _     -> error "vault inconsistent"

  a_k <- getAuthorizedKeys cfg m h un
  pub_content <- readPubSSHFilesFromVault cfg m h un

  putStrLn "diff between vault and authorized keys:"
  print $ intersection
           (fromList $ fmap sel a_k)
           (fromList $ fmap sel pub_content)
  where
    const_RSA_4096_KEY_LENGTH = 716
    sel ln = fmap
                snd .
                Prelude.filter (\p' -> fst p' == const_RSA_4096_KEY_LENGTH) $
                  fmap
                    (\p -> (length $ Ty.toString p, p))
                    (splitOn (Ty.toText " ") (Ty.toText ln))


-- | property check on string conversions (depricated)

prop_scrubbedbytes :: B.ByteString -> Property
prop_scrubbedbytes t =
  True
    ==>  Ty.toSBytes t
    `BA.eq` Ty.toBytes (Ty.toSBytes t)
    ==   Ty.toBytes t
    `BA.eq` Ty.toBytes (Ty.toSBytes t)
    &&   Ty.toSBytes t'
    `BA.eq` Ty.toBytes (Ty.toSBytes t')
    ==   Ty.toBytes t'
    `BA.eq` Ty.toBytes (Ty.toSBytes t')
    &&   Ty.toSBytes t''
    `BA.eq` Ty.toSBytes (Ty.toLUBytes t'')
    ==   Ty.toBytes t''
    `BA.eq` Ty.toBytes (Ty.toLUBytes t'')
  where t'  = Ty.toText t
        t'' = Ty.toBytes t


-- | test setup

genTestConfig :: IO Cfg.Config
genTestConfig = do
  vdir' <- Tu.pwd
  let vdir = Ty.toString $ format fp vdir'
  return Cfg.Config {
        Cfg.dir      = vdir ++ "/tests/data"
      , Cfg.file     = vdir ++ "/tests/data/.vault"
      , Cfg.keystore = vdir ++ "/tests/data/.vault/STORE"
      , Cfg.ttl      = 1
      }


main :: IO ()
main = do
  test0
  dcfg <- genTestConfig
  test1 dcfg
  shellD $ "rm " ++ Cfg.keystore dcfg ++ "/*"
  test2
  quickCheck prop_scrubbedbytes
