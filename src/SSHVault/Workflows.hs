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
    )
    where

import SSHVault.Vault
import SSHVault.Vault.Config as Cfg
import SSHVault.SBytes
import SSHVault.Common

--import Control.Monad.Except
import Control.Exception (SomeException, catch)

import Data.Maybe (fromMaybe)
--import Data.Text (split)
--import Data.List (intercalate)
--import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.Aeson as JSON
import Data.Aeson.Encode.Pretty
import qualified Data.ByteArray as BA

--import System.IO
import System.Exit (ExitCode(..))

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


{-
restoreUserSSHKey :: Cfg.Config -> BA.ScrubbedBytes -> HostName -> UserName -> IO ()
restoreUserSSHKey cfg m h un = catch (
    do
        (v :: Vault) <- decryptVault (toSBytes m) (Cfg.file cfg)
        let users' = getUsers v h
        user' <- case getUser v h un of
            [u''] -> return u''
            _     -> error $ "missing user " ++ un
        let fns = fmap key_file (sshkeys user')
        _ <- map (\ fn -> B.writeFile fn) fns
        return ()
    )
    (\(_ :: SomeException) -> putStrLn "could not rotate SSH key")
-}

-- TODO avoid double entries in ~/.ssh/authorized_keys
rotateUserSSHKey :: Cfg.Config -> AESMasterKey -> HostName -> UserName -> IO ()
rotateUserSSHKey cfg m h un = catch (
    do
        (v :: Vault) <- decryptVault m (Cfg.file cfg)
        let users' = getUsers v h
        user' <- case getUser v h un of
            [u''] -> return u''
            _     -> error $ "missing user " ++ un
        newkey <- genSSHKeyU cfg m h user'
        let newsshkeys = sshkeys user' ++ [newkey]
            newusers   = updateUsers users' $ user' { sshkeys = newsshkeys }
            newve      = updateVaultEntry (head $ filter (\ve -> host ve == h) (vault v)) newusers
            newv       = updateVault v newve
            npub       = key_file newkey ++ ".pub"
            port'      = show . port $ host_data newve
            cmd        = "cat " ++ npub ++ " | ssh -p " ++ port' ++ " " ++ un ++ "@" ++ h
                                        ++ " 'cat >> ~/.ssh/authorized_keys'"
        sshAdd cfg m h un
        r <- procEC cmd
        case r of
            (ExitFailure _, o',  e') -> do
                putStrLn $ "LOG : " ++ o' ++ "\n" ++ e'
                error "failed to ssh"
            (ExitSuccess,    _,  e') -> do
                putStrLn $ "LOG : " ++ show e'
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
chmodSSHFile = chmodFile ("600" :: String)


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
            chmodDir ("700" :: String) d'
            -- procD "chown" [" ", d]
            procD "mkdir" ["-p", ks] -- do not assume that ks is a subdirectory of d
            chmodDir ("700" :: String) ks
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
sshAdd cfg m h u' = catch (
    do
        (v :: Vault) <- decryptVault m (file cfg)
        case filter (\ve -> h == host ve) $ vault v of
            []   -> do putStrLn "host not found"; error "exit"
            [ve] -> case filter (\u'' -> u' == user u'') (users ve) of
                []   -> do putStrLn "user not found"; error "exit"
                [u''] -> do
                    let (max', ph', fn) =
                            ( maximum $ sshkeys u''
                            , B64.decode . toBytes . phrase64 $ max'
                            , key_file max'
                            )
                    ph <- case ph' of
                        Left _ -> do
                            putStrLn "could not decode SSH key passphrase, probably wrong master password"
                            error "exit"
                        Right x' -> decryptAES m x'
                    execSSH (toKeyPhrase ph) ("ssh-add -t " ++ show (Cfg.ttl cfg) ++ " " ++ fn :: String)
                _ -> do putStrLn "vault entry for user inconsistent"; error "exit"
            _ -> do putStrLn "vault entry for host inconsistent"; error "exit"
        return ()
    )
    (\(_ :: SomeException) -> putStrLn $ "failed to ssh-add key for " ++ u' ++ "@" ++ h)
{-
        _ <- return $ map
            (\ s' -> when (substring s' (show e')) (printf (s % "\n") (toText s') :: IO ()))
            [ "host not found"
            , "user not found"
            , "could not decode SSH key passphrase, probably wrong master password"
            , "vault entry for user inconsistent"
            , "vault entry for host inconsistent"
            ]
        --return ()
        printf (s%"\n") (toText $ show e')
-}



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
