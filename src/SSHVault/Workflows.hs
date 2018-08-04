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

--import Data.Maybe (fromMaybe)
import Data.Text (split)
import Data.List (intercalate)
import qualified Data.ByteString.Base64 as B64
import Data.Aeson.Encode.Pretty
--import qualified Data.ByteArray as BA

import qualified Turtle as Tu
import           Turtle.Format
--import qualified Turtle.Prelude as Tu
--import           Turtle.Line (lineToText)



uploadSSHKey :: ToSBytes a => a -> Host -> User -> SSHKey -> ExceptT SSH.SimpleSSHError IO ()
uploadSSHKey _ h u' nkey =
    SSH.openSession h 22 "~/.ssh/known_hosts"
    >>= \ ss -> SSH.authenticateWithKey ss u'' pub priv ph
    >>= \ ss' -> do
        let _ = SSH.sendFile ss' 0o600 pub' "~/.ssh"
            _ = SSH.execCommand ss' $ "cat ~/.ssh/" ++ pub'' ++ " >> ~/.ssh/authorized_keys"
            _ = SSH.execCommand ss' $ "rm ~/.ssh/" ++ pub''
        SSH.closeSession ss'
        --return ()
    where
        u'' = user u'
        s' = sshkey u'
        ph = case B64.decode . toBytes $ phrase64 s' of
            Left _ -> error "uploadSSHKey failed to B64.decode key passphrase"
            Right s0 -> toString s0
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

genSSHKey :: ToSBytes a => Cfg.Config -> a -> Host -> User -> IO SSHKey
genSSHKey cfg m h u' = do
    printf "[*] generate new SSH key password\n"
    pw' <- randS 20
    pw'' <- if (toBytes m) == "" then return $ toBytes pw' else encryptAES (toBytes m) $ toBytes pw'
    let pw = toString $ B64.encode pw''
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


initVault :: IO ()
initVault = catch
    (do
        pw  <- getKeyPhrase
        cfg <- Cfg.genDefaultConfig
        let d' = toText $ dir cfg
            ks = toText $ keystore cfg
            v  = file cfg
        procD "mkdir" ["-p", d']
        chmodDirR ("700" :: String) d'
        -- procD "chown" [" ", d] Tu.empty
        procD "mkdir" ["-p", ks] -- do not assume that ks is a subdirectory of d
        chmodDirR ("700" :: String) ks
        -- procD "chown" [" ", d] Tu.empty
        encryptVault (toSBytes pw) v Vault {vault = []}
    )
    (\(e' :: SomeException) -> do
        printf w $ "could not initialize vault file: " ++ show e'
        return ()
    )


printVault :: Cfg.Config -> IO ()
printVault _ = catch
    (  -- TODO add options to choose config
     do
        pw  <- getKeyPhrase
        cfg <- Cfg.genDefaultConfig
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