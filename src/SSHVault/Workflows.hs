-- :set -XOverloadedStrings
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DuplicateRecordFields #-}

module SSHVault.Workflows
    ( initVault
    , printVault
    , uploadSSHKey
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
--import SSHVault.Vault.Queue
import SSHVault.SBytes
import SSHVault.Common

--import Control.Monad.Except
import Control.Exception (SomeException, catch)

import Data.Maybe (fromMaybe)
--import Data.Text (split)
--import Data.List (intercalate)
--import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Base64 as B64
import qualified Data.Aeson as JSON
import Data.Aeson.Encode.Pretty
import qualified Data.ByteArray as BA

--import System.IO

import qualified Turtle as Tu
import Turtle.Prelude (testfile)
import Turtle.Format



getSSHKeyphrase :: BA.ScrubbedBytes -> User -> IO BA.ScrubbedBytes
getSSHKeyphrase m u' = case B64.decode . toBytes $ phrase64 s' of
    Left _   -> error "failed to b64decode SSH key passphrase"
    Right s0 -> decryptAES m s0
    where
        s' = maximum $ sshkeys u'


-- TODO avoid double entries in ~/.ssh/authorized_keys
-- TODO add port parameter
uploadSSHKey :: Cfg.Config -> BA.ScrubbedBytes -> HostName -> User -> SSHKey -> IO ()
uploadSSHKey cfg m h u' nkey = catch (
    do
        ph <- getSSHKeyphrase m u'
        execExp cfg "upload-sshkey"
            [ "spawn bash -c \"cat " ++ npub
            ++ " | ssh -i " ++ priv ++ " " ++ u'' ++ "@" ++ h
            ++ " 'cat >> ~/.ssh/authorized_keys'\""
            , "expect \"Enter passphrase\""
            , "send \"" ++ toString ph ++ "\\r\""
            , "expect eof"
            ]
    )
    (\(_ :: SomeException) ->
        print ("could not upload SSH key" :: String)
    )
    where
            u''  = user u'
            s'   = maximum $ sshkeys u'
            priv = key_file s'
            npub = key_file nkey ++ ".pub"


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
    pw' <- randS 20
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
    (\(_ :: SomeException) ->
        print ("could not initialize vault file" :: String)
    )


printVault :: Cfg.Config -> IO ()
printVault cfg = catch (
     do
        pw  <- getKeyPhrase
        (v :: Vault) <- decryptVault (toSBytes pw) (file cfg)
        printf (s%"\n") . toText $ encodePretty v
    )
    (\(_ :: SomeException) ->
        print ("could not print vault" :: String)
    )


sshAdd :: HostName -> UserName -> IO ()
sshAdd h u' = catch (
    do
        cfg          <- genDefaultConfig
        m            <- getKeyPhrase
        (v :: Vault) <- decryptVault m (file cfg)
        case filter (\ve -> h == host ve) $ vault v of
            []   -> error "host not found"
            [ve] -> case filter (\u'' -> u' == user u'') (users ve) of
                []   -> error "user not found"
                [u''] -> do
                    let (max, ph', fn, exp') =
                            ( maximum $ sshkeys u''
                            , B64.decode . toBytes . phrase64 $ max
                            , key_file max
                            , "ssh-add"
                            )
                    ph <- case ph' of
                        Left _ -> error "could not decode SSH key passphrase, probably wrong master password"
                        Right x' -> decryptAES m x'
                    execExp cfg exp'
                            [ "spawn ssh-add -t 60 " ++ fn
                            , "expect \"Enter passphrase\""
                            , "send \"" ++ toString ph ++ "\\r\""
                            , "expect eof"
                            ]

            _ -> error "vault entry for host inconsistent"
        return ()
    )
    (\(_ :: SomeException) -> --do
        printf (s%"\n") . toText $ "failed to ssh-add key for " ++ u' ++ "@" ++ h
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
    )


insertSSHKey :: ToSBytes a => Cfg.Config -> a -> String -> IO ()
insertSSHKey cfg m s' = do
    (v :: Vault)       <- decryptVault m (Cfg.file cfg)
    (ve :: VaultEntry) <- return
        . fromMaybe (error "failed to JSON.decode the given input")
        . JSON.decode $ toLUBytes s'
    case filter (\h -> h == host ve) $ fmap host (vault v) of
        [] -> encryptVault
                (toSBytes m) (Cfg.file cfg) (Vault (vault v ++ [ve]))
        _  -> print $ "failed to insert host " ++ host ve ++ ": already in vault"


b64EncryptSSHKeyPassphrase :: IO ()
b64EncryptSSHKeyPassphrase = do
    putStrLn "1. Masterpassword"
    m <- getKeyPhrase
    putStrLn "2. SSH key"
    k    <- getLine
    aesk <- encryptAES m $ toBytes k
    let b64aesk = B64.encode $ toBytes aesk
    case B64.decode b64aesk of
        Left  _ -> print ("could not b64encode/encrypt" :: String)
        Right x' -> do
            y <- decryptAES m x'
            if toString y == k then print $ toString b64aesk else print ("encode/decode error" :: String)
