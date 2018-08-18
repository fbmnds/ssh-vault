-- :set -XOverloadedStrings
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DuplicateRecordFields #-}

module SSHVault.Workflows
    ( InsertMode (..)
    , initVault
    , printVault
    , rotateUserSSHKey
    , genSSHFilename
    , chmodSSHFile
    , genSSHKeyU
    , getSSHKeyphrase
    , sshAdd
    , insertSSHKey
    , b64EncryptSSHKeyPassphrase
    , readPubSSHFilesFromVault
    , getAuthorizedKeys
    , writeUserSSHKeys
    , confirmSSHAccess
    )
    where

import SSHVault.Vault
import SSHVault.Vault.Config as Cfg
import SSHVault.SBytes
import SSHVault.Common

import Control.Monad
import Control.Exception (SomeException, catch)
-- import Control.Concurrent (threadDelay)

import Data.Set (fromList, intersection)
import Data.Maybe (fromMaybe)
import Data.List (intercalate)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.Aeson as JSON
import Data.Aeson.Encode.Pretty
import qualified Data.ByteArray as BA
import qualified Data.Text as T
--import Data.Text (split)

import System.IO
import System.Exit (ExitCode(..))

import Foreign
import Foreign.C.Types
import Foreign.C.String

import qualified Turtle as Tu
import Turtle.Prelude (testfile)


data InsertMode
    = Insert
    | Replace



getSSHKeyphrase :: AESMasterKey -> User -> IO (BA.ScrubbedBytes, String)
getSSHKeyphrase m u' = case B64.decode . toBytes $ phrase64 max' of
    Left _   -> error "failed to b64decode SSH key passphrase"
    Right s0 -> do
        ph <- decryptAES m s0
        return (ph, key_file max')
    where
        max' = maximum $ sshkeys u'


rotateUserSSHKey :: Cfg.Config -> AESMasterKey -> HostName -> UserName -> IO ()
rotateUserSSHKey cfg m h un = catch (
    do
        --a_k <- getAuthorizedKeys cfg m h un
        --print a_k
        (v :: Vault) <- decryptVault m (Cfg.file cfg)
        let users' = getUsers v h
        user' <- case getUser v h un of
            [u''] -> return u''
            _     -> error $ "missing user " ++ un
        newkey <- genSSHKeyU cfg m h user'
        let newsshkeys   = sshkeys user' ++ [newkey]
            newusers     = updateUsers users' $ user' { sshkeys = newsshkeys }
            newve        = updateVaultEntry (head $ filter (\ve -> host ve == h) (vault v)) newusers
            newv         = updateVault v newve
            -- npub          = key_file newkey ++ ".pub"
            port'        = show . port $ host_data newve
            new_a_k      = external_keys user' ++ [key_pub newkey]
            new_a_k_file = Cfg.dir cfg ++ "/authorized_keys"
            cmd          = "cat " ++ new_a_k_file
                                  ++ " | ssh -p " ++ port' ++ " " ++ un ++ "@" ++ h
                                  ++ " 'cat > ~/.ssh/authorized_keys'"
        procD "touch" [new_a_k_file]
        chmodSSHFile new_a_k_file
        B.writeFile new_a_k_file .toBytes $ intercalate "\n" new_a_k
        -- use old key
        -- shellD ("ssh-add -L" :: String)
        sshAdd (cfg { Cfg.ttl = 1 }) m h un
        -- shellD ("ssh-add -L" :: String)
        -- use old key
        r <- procEC cmd
        case r of
            (ExitFailure _, o',  e') -> do
                putStrLn $ "LOG : " ++ o' ++ "\n" ++ e'
                error "failed to ssh"
            (ExitSuccess,    _,  e') -> do
                putStrLn $ "LOG : " ++ show e'
                -- persist new key in vault
                encryptVault m (Cfg.file cfg) newv
    )
    (\(_ :: SomeException) -> putStrLn "could not rotate SSH key")


genSSHFilename :: Cfg.Config -> HostName -> User -> IO String
genSSHFilename cfg h u' = do
    date <- getUTC
    let ud = user u' ++ date
    let kn = split4 . take2nd . genSHA256 . toText $ h ++ ud
    let fn = Cfg.keystore cfg ++ "/id_" ++ kn
    return fn


chmodSSHFile :: ToSBytes a => a -> IO ()
chmodSSHFile = chmodF ("600" :: String)


genSSHKeyU :: Cfg.Config -> AESMasterKey -> HostName -> User -> IO SSHKey
genSSHKeyU cfg m h u' = catch (do
    putStrLn "[*] generate new SSH key password"
    ph' <- randS 32                                     -- unscrubbed
    ph'' <- encryptAES m ph'
    let ph = toKeyPhrase64 . B64.encode $ toBytes ph''  -- unscrubbed, but encrypted
    putStrLn "[*] generate new SSH key file name"
    fn <- genSSHFilename cfg h u'
    putStrLn "[*] ssh-keygen new SSH priv/pub keys"
    procD
        "ssh-keygen"
        [ "-n", user u' ++ "@" ++ h
        , "-t", "rsa"
        , "-b", "4096"
        , "-f", fn
        , "-P", ph'
        ]
    putStrLn "[+] new SSH keys generated"
    chmodSSHFile fn
    putStrLn "[+] chmod 600 on new SSH private key file"
    c' <- readFile fn
    t' <- getUTC
    c'' <- readFile $ fn ++ ".pub"
    return SSHKey { phrase64 = ph, key_file = fn, key_priv = c', key_pub = c'', created_at = t' }
    )
    (\(e' :: SomeException) -> do
        putStrLn $ "LOG: failed in genSSHKeyU\n" ++ show e'
        error "could not generate new SSH key password")

initVault :: Cfg.Config -> IO ()
initVault cfg = catch (
    do
        let v  = file cfg
        b' <- testfile (Tu.fromString v)
        if b' then print ("vault file exists. " ++ v)
        else do
            pw  <- getAESMasterKeyU
            let d' = toText $ dir cfg
                ks = toText $ keystore cfg
            procD "mkdir" ["-p", d']
            chmodD ("700" :: String) d'
            -- procD "chown" [" ", d]
            procD "mkdir" ["-p", ks] -- do not assume that ks is a subdirectory of d
            chmodD ("700" :: String) ks
            -- procD "chown" [" ", d]
            encryptVault pw v Vault {vault = []}
    )
    (\(_ :: SomeException) -> putStrLn ("could not initialize vault file" :: String))


printVault :: Cfg.Config -> IO ()
printVault cfg = catch (
     do
        pw  <- getAESMasterKeyU
        (v :: Vault) <- decryptVault pw (file cfg)
        putStrLn . toString $ encodePretty v
    )
    (\(_ :: SomeException) -> putStrLn ("could not print vault" :: String))


sshAdd :: Cfg.Config -> AESMasterKey -> HostName -> UserName -> IO ()
sshAdd cfg m h un = catch
    (do
        (v :: Vault) <- decryptVault m (file cfg)
        case filter (\ve -> h == host ve) $ vault v of
            [] -> do
                putStrLn "host not found"
                error "exit"
            [ve] -> case filter (\u'' -> un == user u'') (users ve) of
                [] -> do
                    putStrLn "user not found"
                    error "exit"
                [u''] -> do
                    let (max', ph', fn) =
                            ( maximum $ sshkeys u''
                            , B64.decode . toBytes . phrase64 $ max'
                            , key_file max'
                            )
                    ph <- case ph' of
                        Left _ -> do
                            putStrLn
                                "could not decode SSH key passphrase, probably wrong master password"
                            error "exit"
                        Right x' -> decryptAES m x'
                    d' <- newCString $ show $ Cfg.ttl cfg
                    p  <- newCString fn
                    e' <- newCString "nter passphrase"
                    a  <- newCString $ toString ph
                    _  <- ssh_add d' p e' a
                    (ec, o, e'') <- procEC "ssh-add -L"
                    case ec of
                        ExitFailure _ -> error "LOG : FFI call to ssh-add failed"
                        ExitSuccess   ->
                            if substring fn o then
                                return ()
                            else do
                                putStrLn $ "LOG: " ++ e''
                                error "LOG : FFI call to ssh-add failed"
                _ -> do
                    putStrLn "vault entry for user inconsistent"
                    error "exit"
            _ -> do
                putStrLn "vault entry for host inconsistent"
                error "exit"
        return ()
    )
    (\(_ :: SomeException) ->
        putStrLn $ "failed to ssh-add key for " ++ un ++ "@" ++ h
    )


insertSSHKey :: InsertMode -> Cfg.Config -> AESMasterKey -> String -> IO ()
insertSSHKey mode cfg m s' = do
    (v :: Vault)       <- decryptVault m (Cfg.file cfg)
    (ve :: VaultEntry) <- return
        . fromMaybe (error "failed to JSON.decode the given input")
        . JSON.decode $ toLUBytes s'
    case filter (\ve' -> host ve' == host ve) (vault v) of
        []  -> encryptVault m (Cfg.file cfg) (Vault (vault v ++ [ve]))
        _ -> case mode of
            Replace -> do
                let ves = filter (\ve' -> host ve' /= host ve) (vault v)
                encryptVault m (Cfg.file cfg) (Vault (ves ++ [ve]))
            Insert  -> do
                putStrLn "failed to insert vault entry (duplicate)"
                error "exit"


b64EncryptSSHKeyPassphrase :: IO ()
b64EncryptSSHKeyPassphrase = do
    putStrLn "1. Vault password"
    m <- getAESMasterKeyU
    putStrLn "2. SSH key passphrase"
    k    <- getLine
    aesk <- encryptAES m $ toBytes k
    let b64aesk = B64.encode $ toBytes aesk
    case B64.decode b64aesk of
        Left  _ -> putStrLn "could not b64encode/encrypt"
        Right x' -> do
            y <- decryptAES m x'
            if toString y == k then putStrLn $ toString b64aesk else putStrLn "encode/decode error"


readPubSSHFilesFromVault :: Cfg.Config -> AESMasterKey -> HostName -> UserName -> IO [String]
readPubSSHFilesFromVault cfg m h un = do
  (v :: Vault) <- decryptVault m (Cfg.file cfg)
  u' <- case getUser v h un of
      [u''] -> return u''
      []    -> error $ "missing user " ++ un
      _     -> error "vault inconsistent"
  return $ fmap key_pub (sshkeys u')


getAuthorizedKeys :: Cfg.Config -> AESMasterKey -> HostName -> UserName -> IO [T.Text]
getAuthorizedKeys cfg m h un = do
  let cmd  = "ssh " ++ un ++ "@" ++ h ++ " 'cat ~/.ssh/authorized_keys'"
  sshAdd (cfg { Cfg.ttl = 1 }) m h un
  r <- procEC cmd
  a_k <- case r of
      (ExitFailure _, o', e') -> do
        putStrLn $ "LOG :" ++ show e'
        unless (null o') $ putStrLn $ "LOG :" ++ show o'
        error "failed to retrieve authorized_keys"
      (ExitSuccess  , o', e') -> do
        unless (null e') $ putStrLn $ "LOG :" ++ show e'
        return o'
  case T.splitOn "\n" (toText a_k) of
    [] -> error "retrieved empty authorized_keys file"
    ks -> return ks


writeUserSSHKeys :: AESMasterKey -> Vault -> HostName -> UserName -> IO ([SSHKey], [String], [String])
writeUserSSHKeys m v h un = do
  let sks = concatMap sshkeys $ getUser v h un
  rs <- mapM (\sk -> do ec <-  writeSSHKey m sk; return (key_file sk,ec)) sks
  rs' <- foldM (\ acc (fn,ec) -> case ec of
    ExitSuccess -> return (fst acc ++ [fn], snd acc)
    _           -> return (fst acc, snd acc ++ [fn])) ([],[]) rs
  mapM_ (\ err -> putStrLn $ "LOG: could not write " ++ err) (snd rs')
  return (sks, fst rs', snd rs')
    where
        writeSSHKey :: AESMasterKey -> SSHKey -> IO ExitCode
        writeSSHKey m' sk = catch (do
          let priv = key_file sk
              pub  = priv ++ ".pub"
          ph <- case B64.decode . toBytes $ phrase64 sk of
            Left _   -> error "failed to b64decode SSH key passphrase"
            Right s0 -> do
                ph' <- decryptAES m' s0
                return $ toString ph'
          B.writeFile priv (toBytes $ key_priv sk)
          chmodF ("600" :: String) (priv :: String)
          _ <- procEC $ "ssh-keygen -f " ++ priv ++ " -y -P " ++ ph ++ " > " ++ pub
          chmodF ("644" :: String) (pub :: String)
          return ExitSuccess
          )
          (\(e' :: SomeException) -> do
            putStrLn $ "LOG: could not write SSH key:" ++ key_file sk ++ "(.pub)\n" ++ show e'
            return (ExitFailure 1))


confirmSSHAccess :: Cfg.Config -> AESMasterKey -> HostName -> UserName -> IO String
confirmSSHAccess cfg m h un = do
  a_k <- getAuthorizedKeys cfg m h un
  pub_content <- readPubSSHFilesFromVault cfg m h un
  case concat $ intersection
           (fromList $ fmap sel a_k)
           (fromList $ fmap sel pub_content) of
    [] -> return "Access failed"
    _  -> return "Access confirmed"
  where
    const_RSA_4096_KEY_LENGTH = 716
    sel ln = fmap
                snd .
                Prelude.filter (\p' -> fst p' == const_RSA_4096_KEY_LENGTH) $
                  fmap
                    (\p -> (length $ toString p, p))
                    (T.splitOn " " (toText ln))

