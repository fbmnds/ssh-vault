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
    , genSSHKey
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
import Control.Exception (SomeException, catch, bracket_)

import Data.Maybe (fromMaybe)
--import Data.Text (split)
--import Data.List (intercalate)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.Aeson as JSON
import Data.Aeson.Encode.Pretty
import qualified Data.ByteArray as BA

import System.IO
import System.Exit (ExitCode(..))

import qualified Turtle as Tu
import Turtle.Prelude (testfile)
import Turtle.Format


data InsertMode
    = Insert
    | Replace



getSSHKeyphrase :: BA.ScrubbedBytes -> User -> IO (BA.ScrubbedBytes, String)
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
rotateUserSSHKey :: Cfg.Config -> BA.ScrubbedBytes -> HostName -> UserName -> IO ()
rotateUserSSHKey cfg m h un = catch (
    do
        (v :: Vault) <- decryptVault (toSBytes m) (Cfg.file cfg)
        let users' = getUsers v h
        user' <- case getUser v h un of
            [u''] -> return u''
            _     -> error $ "missing user " ++ un
        newkey <- genSSHKey cfg m h user'
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
            (ExitSuccess  , o', e') -> do
                putStrLn $ "LOG : " ++ show e'
                encryptVault m (Cfg.file cfg) newv
    )
    (\(_ :: SomeException) -> putStrLn "could not rotate SSH key")


genSSHFilename :: Cfg.Config -> HostName -> User -> IO String
genSSHFilename cfg h u' = do
    date <- Tu.date
    let ud = format (s % w) (toText . user $ u') date
    let kn = split4 . take2nd . genSHA256 $ format (s % s) (toText h) ud
    let fn = Cfg.keystore cfg ++ "/id_" ++ kn
    return fn


chmodSSHFile :: ToSBytes a => a -> IO ()
chmodSSHFile = chmodFile ("600" :: String)


genSSHKey :: Cfg.Config -> BA.ScrubbedBytes -> HostName -> User -> IO SSHKey
genSSHKey cfg m h u' = do
    printf "[*] generate new SSH key password\n"
    pw' <- randS 32
    pw'' <- if toBytes m == ""
        then return $ toSBytes pw' -- TODO rewrite test1, remove empty m
        else encryptAES m pw'
    let pw = toString . B64.encode $ toBytes pw''
    printf "[*] generate new SSH key file name\n"
    fn <- genSSHFilename cfg h u'
    printf "[*] ssh-keygen new SSH key file\n"
    procD
        "ssh-keygen"
        [ "-n", user u' ++ "@" ++ h
        , "-t", "rsa"
        , "-b", "4096"
        , "-f", fn
        , "-P", pw'
        ]
    printf "[+] new SSH secrets generated\n"
    chmodSSHFile fn
    printf "[+] chmod 600 on new SSH file\n"
    c' <- readFile fn
    t' <- getUTC
    return SSHKey { phrase64 = pw, key_file = fn, key_content = c', created_at = t' }


initVault :: Cfg.Config -> IO ()
initVault cfg = catch (
    do
        let v  = file cfg
        b' <- testfile (Tu.fromString v)
        if b' then print ("vault file exists. " ++ v)
        else do
            pw  <- getKeyPhrase
            let d' = toText $ dir cfg
                ks = toText $ keystore cfg
            procD "mkdir" ["-p", d']
            chmodDir ("700" :: String) d'
            -- procD "chown" [" ", d]
            procD "mkdir" ["-p", ks] -- do not assume that ks is a subdirectory of d
            chmodDir ("700" :: String) ks
            -- procD "chown" [" ", d]
            encryptVault (toSBytes pw) v Vault {vault = []}
    )
    (\(_ :: SomeException) -> print ("could not initialize vault file" :: String))


printVault :: Cfg.Config -> IO ()
printVault cfg = catch (
     do
        pw  <- getKeyPhrase
        (v :: Vault) <- decryptVault (toSBytes pw) (file cfg)
        printf (s%"\n") . toText $ encodePretty v
    )
    (\(_ :: SomeException) -> print ("could not print vault" :: String))


sshAdd :: ToSBytes a => Cfg.Config -> a -> HostName -> UserName -> IO ()
sshAdd cfg m h u' = catch (
    do
        (v :: Vault) <- decryptVault m (file cfg)
        case filter (\ve -> h == host ve) $ vault v of
            []   -> do print "host not found"; error "exit"
            [ve] -> case filter (\u'' -> u' == user u'') (users ve) of
                []   -> do print "user not found"; error "exit"
                [u''] -> do
                    let (max', ph', fn) =
                            ( maximum $ sshkeys u''
                            , B64.decode . toBytes . phrase64 $ max'
                            , key_file max'
                            )
                    ph <- case ph' of
                        Left _ -> do
                            print "could not decode SSH key passphrase, probably wrong master password"
                            error "exit"
                        Right x' -> decryptAES (toSBytes m) x'
                    execSSH ph ("ssh-add -t 90 " ++ fn :: String)
                _ -> do print "vault entry for user inconsistent"; error "exit"
            _ -> do print "vault entry for host inconsistent"; error "exit"
        return ()
    )
    (\(_ :: SomeException) -> printf (s%"\n") . toText $ "failed to ssh-add key for " ++ u' ++ "@" ++ h)
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



insertSSHKey :: ToSBytes a => InsertMode -> Cfg.Config -> a -> String -> IO ()
insertSSHKey mode cfg m s' = do
    (v :: Vault)       <- decryptVault m (Cfg.file cfg)
    (ve :: VaultEntry) <- return
        . fromMaybe (error "failed to JSON.decode the given input")
        . JSON.decode $ toLUBytes s'
    case filter (\ve' -> host ve' == host ve) (vault v) of
        []  -> encryptVault
                (toSBytes m) (Cfg.file cfg) (Vault (vault v ++ [ve]))
        _ -> case mode of
            Replace -> do
                let ves = filter (\ve' -> host ve' /= host ve) (vault v)
                encryptVault
                    (toSBytes m) (Cfg.file cfg) (Vault (ves ++ [ve]))
            Insert  -> do
                putStrLn "failed to insert vault entry (duplicate)"
                error "exit"



b64EncryptSSHKeyPassphrase :: IO ()
b64EncryptSSHKeyPassphrase = do
    putStrLn "1. Vault password"
    m <- getKeyPhrase
    putStrLn "2. SSH key passphrase"
    k    <- getLine
    aesk <- encryptAES m $ toBytes k
    let b64aesk = B64.encode $ toBytes aesk
    case B64.decode b64aesk of
        Left  _ -> print ("could not b64encode/encrypt" :: String)
        Right x' -> do
            y <- decryptAES m x'
            if toString y == k then print $ toString b64aesk else print ("encode/decode error" :: String)
