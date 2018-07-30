-- :set -XOverloadedStrings
{-# LANGUAGE OverloadedStrings #-}
module SSHVault.Workflows
    (
      uploadSSHKey
    , genSSHFilename
    , chmodSSHFile
    , genSSHKey
    )
    where

import SSHVault.Vault
import SSHVault.Vault.Config as Cfg
import SSHVault.SBytes
import SSHVault.Common

import qualified Network.SSH.Client.SimpleSSH as SSH

--import Data.Maybe (fromMaybe)
import Data.Text (split)
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
        ph = passphrase s'
        priv = key_file s'
        pub = priv ++ ".pub"
        pub' = key_file nkey ++ ".pub"
        pub'' = toString . last $ split (=='/') (toText pub')


genSSHFilename :: Cfg.Config -> QueueEntry -> IO String
genSSHFilename cfg qe = do
    date <- Tu.date
    let ud = format (s%w) (toText . user $ snd qe) date
    let kn = toText . genSHA256 $ format (s %s) (toText $ fst qe) ud
    let fn = format (s % s % s) (toText $ Cfg.keystore cfg) "/id" kn
    return $ toString fn


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

genSSHKey :: Cfg.Config -> QueueEntry -> IO SSHKey
genSSHKey cfg qe = do
    printf "[*] generate new SSH key password\n"
    pw <- randS 20
    printf "[*] generate new SSH key file name\n"
    fn <- genSSHFilename cfg qe
    printf "[*] ssh-keygen new SSH key file\n"
    procD
        "ssh-keygen"
        [ "-n", user $ snd qe
        , "-t", "rsa"
        , "-b", "4096"
        , "-f", fn
        , "-P", pw
        ]
        Tu.empty
    printf "[+] new SSH secrets generated\n"
    chmodSSHFile fn
    printf "[+] chmod 600 on new SSH file\n"
    return SSHKey { passphrase = pw, key_file = fn }
