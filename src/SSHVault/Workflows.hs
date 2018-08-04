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
    )
    where

import SSHVault.Vault
import SSHVault.Vault.Config as Cfg
--import SSHVault.Vault.Queue
import SSHVault.SBytes
import SSHVault.Common

import Control.Exception (SomeException, catch)
import qualified Network.SSH.Client.SimpleSSH as SSH

--import Data.Maybe (fromMaybe)
import Data.Text (split)
import qualified Data.ByteString.Base64 as B64
import Data.Aeson.Encode.Pretty
--import qualified Data.ByteArray as BA

import qualified Turtle as Tu
import           Turtle.Format
--import qualified Turtle.Prelude as Tu
--import           Turtle.Line (lineToText)



--uploadSSHKey :: QueueEntry -> SSHKey -> IO SSH.Session
uploadSSHKey qe nkey =
    SSH.openSession (fst qe) 22 "~/.ssh/known_hosts"
    >>= \ ss -> SSH.authenticateWithKey ss u' pub priv ph
    >>= \ ss' ->
        let _ = SSH.sendFile ss' 0o600 pub' "~/.ssh" in
        (\ ss'' ->
            let _ = SSH.execCommand ss'' $ "cat ~/.ssh/" ++ pub'' ++ " >> ~/.ssh/authorized_keys"
                _ = SSH.execCommand ss'' $ "rm ~/.ssh/" ++ pub''
        in return ())
        ss
      where
        u' = user $ snd qe
        s' = sshkey $ snd qe
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

genSSHKey :: Cfg.Config -> Host -> User -> IO SSHKey
genSSHKey cfg h u' = do
    printf "[*] generate new SSH key password\n"
    pw' <- randS 20
    let pw = toString . B64.encode $ toBytes pw'
    printf "[*] generate new SSH key file name\n"
    fn <- genSSHFilename cfg h u'
    printf "[*] ssh-keygen new SSH key file\n"
    procD
        "ssh-keygen"
        [ "-n", user u' ++ "@" ++ h
        , "-t", "rsa"
        , "-b", "4096"
        , "-f", fn
        , "-P", pw
        ]
        Tu.empty
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
        procD "mkdir" ["-p", d'] Tu.empty
        chmodDirR ("700" :: String) d'
        -- procD "chown" [" ", d] Tu.empty
        procD "mkdir" ["-p", ks] Tu.empty -- do not assume that ks is a subdirectory of d
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
