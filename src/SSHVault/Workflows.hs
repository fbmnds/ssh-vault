-- :set -XOverloadedStrings
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module SSHVault.Workflows
    ( initVault
    , printVault
    , uploadSSHKey
    , genSSHFilename
    , chmodSSHFile
    , genSSHKey
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

import Control.Monad.Except
import Control.Exception (SomeException, catch)
import qualified Network.SSH.Client.SimpleSSH as SSH

import Data.Maybe (fromMaybe)
import Data.Text (split)
import Data.List (intercalate)
import qualified Data.ByteString.Base64 as B64
import qualified Data.Aeson as JSON
import Data.Aeson.Encode.Pretty
import qualified Data.ByteArray as BA

import qualified Turtle as Tu
import           Turtle.Format



getSSHKey :: BA.ScrubbedBytes -> User -> IO String
getSSHKey m u' = do
    ph <- case B64.decode . toBytes $ phrase64 s' of
        Left _ -> error "failed to B64.decode key passphrase"
        Right s0 -> decryptAES m s0
    return $ toString ph
    where
        s' = sshkey u'

-- TODO avoid double entries in ~/.ssh/authorized_keys
uploadSSHKey :: Host -> User -> String -> SSHKey -> ExceptT SSH.SimpleSSHError IO ()
uploadSSHKey h u' ph nkey = do   -- TODO use bracket
    ss <- SSH.openSession h 22 "~/.ssh/known_hosts"
    ss1 <- SSH.authenticateWithKey ss u'' pub priv ph
    _ <- SSH.execCommand ss1 $ "cat ~/.ssh/" ++ pub'' ++ " >> ~/.ssh/authorized_keys"
    _ <- SSH.execCommand ss1 $ "rm ~/.ssh/" ++ pub''
    SSH.closeSession ss1
    where
        u'' = user u'
        s' = sshkey u'
        priv = key_file s'
        pub = priv ++ ".pub"
        pub' = key_file nkey ++ ".pub"
        pub'' = toString . last $ split (=='/') (toText pub')


genSSHFilename :: Cfg.Config -> Host -> User -> IO String
genSSHFilename cfg h u' = do
    date <- Tu.date
    let ud = format (s % w) (toText . user $ u') date
    let kn = split4 . take2nd . genSHA256 $ format (s % s) (toText h) ud
    let fn = Cfg.keystore cfg ++ "/id_" ++ kn
    return fn


chmodSSHFile :: ToSBytes a => a -> IO ()
chmodSSHFile = chmodFile ("600" :: String)


{-
+ getConfig ()  -> {HOME, vault_key} = cfg

procQueueEntry cfg q    -- q :: QueueEntry = "VaultEntry reduced to single user"
(+)    genSSHKeyFileName q -> new_key_file -- name convention id_sha256(time)
+    touchNewKeyFile new_key_file chmod 600 u+rw-,go-rwx --> exit
+    genKeySecret -> randS
+    genSSHKey new_file
    updateVault?Queue?
    safeVault fn
    uploadKey q

-}

genSSHKey :: Cfg.Config -> BA.ScrubbedBytes -> Host -> User -> IO SSHKey
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
    return SSHKey { phrase64 = pw, key_file = fn }


initVault :: Cfg.Config -> IO ()
initVault cfg = catch
    (do
        pw  <- getKeyPhrase
        let d' = toText $ dir cfg
            ks = toText $ keystore cfg
            v  = file cfg
        procD "mkdir" ["-p", d']
        chmodDirR ("700" :: String) d'
        -- procD "chown" [" ", d]
        procD "mkdir" ["-p", ks] -- do not assume that ks is a subdirectory of d
        chmodDirR ("700" :: String) ks
        -- procD "chown" [" ", d]
        encryptVault (toSBytes pw) v Vault {vault = []}
    )
    (\(e' :: SomeException) -> do
        printf w $ "could not initialize vault file: " ++ show e'
        return ()
    )


printVault :: Cfg.Config -> IO ()
printVault cfg = catch
    (
     do
        pw  <- getKeyPhrase
        let v = file cfg
        (v' :: Vault) <- decryptVault (toSBytes pw) v
        printf (s%"\n") . toText $ encodePretty v'
    )
    (\(e' :: SomeException) -> do
        printf w $ "could not print vault: " ++ show e' ++ "\n"
        return ()
    )


sshAdd :: String -> String -> IO ()
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
                    let (ph', fn, exp') =
                            ( B64.decode . toBytes . phrase64 $ sshkey u''
                            , key_file $ sshkey u''
                            , dir cfg ++ "/ssh-add.exp"
                            )
                    ph <- case ph' of
                        Left _ -> error "could not decode SSH key passphrase, probably wrong master password"
                        Right x' -> decryptAES m x'
                    _ <- procD "touch" [exp']
                    _ <- chmodFile ("600" :: String) exp'
                    let ls =
                            [ "spawn ssh-add -t 60 " ++ fn
                            , "expect \"Enter passphrase\""
                            , "send \"" ++ toString ph ++ "\\r\""
                            , "expect eof"
                            ]
                    _ <- writeFile exp' (intercalate "\n" ls)
                    _ <- procD "expect" ["-f", exp']
                    _ <- procD "rm" [exp']
                    return ()
                _ -> error "vault entry for user inconsistent"
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
        _  -> error $ "failed to insert host " ++ host ve ++ ": already in vault"

b64EncryptSSHKeyPassphrase :: IO ()
b64EncryptSSHKeyPassphrase = do
    putStrLn "1. Masterpassword"
    m <- getKeyPhrase
    putStrLn "2. SSH key"
    k    <- getLine
    aesk <- encryptAES m $ toBytes k
    let b64aesk = B64.encode $ toBytes aesk
    case B64.decode b64aesk of
        Left  _ -> print "could not b64encode/encrypt"
        Right x -> do
            y <- decryptAES m x
            print y
