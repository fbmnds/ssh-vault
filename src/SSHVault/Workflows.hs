-- :set -XOverloadedStrings
{-# LANGUAGE OverloadedStrings #-}
module SSHVault.Workflows
    (
      uploadKeyCmd
    , genSSHFilename
    , chmodSSHFile
    , genSSHSecrets

    )
    where

import SSHVault.Vault
import SSHVault.Vault.Config as Cfg
import SSHVault.SBytes
import SSHVault.Common

import qualified Network.SSH.Client.SimpleSSH as SSH

--import Data.Maybe (fromMaybe)
import Data.Text (Text)
--import qualified Data.ByteArray as BA

import qualified Turtle as Tu
import           Turtle.Format
--import qualified Turtle.Prelude as Tu
--import           Turtle.Line (lineToText)


uploadKeyCmd :: Cfg.Config -> QueueEntry -> Text -> Text
uploadKeyCmd cfg qe newKeyFile = format (s % s % s) p1 p2 p3
    where
        h = fst qe
        u' = user $ snd qe
        ks = toText $ Cfg.keystore cfg
        kf = toText . key_file . secrets $ snd qe
        p1 = format ("cat " % s % "/" % s % ".pub") ks newKeyFile
        p2 = format (" | ssh -i " % s % "/" % s) ks kf
        p3 =
          if u' == "root" then
            format (" root@" % s % " \"cat >> /root/.ssh/authorized_keys\"") h
          else
            format (" " % s % "@" % s % " \"cat >> /home/" % s % "/.ssh/authorized_keys\"") u' h u'


genSSHFilename :: Cfg.Config -> QueueEntry -> IO Text
genSSHFilename cfg qe = do
    date <- Tu.date
    let ud = format (s%w) (user $ snd qe) date
    let kn = toText . genSHA256 $ format (s %s) (fst qe) ud
    let fn = format (s % s % s) (toText $ Cfg.keystore cfg) "/id" kn
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

genSSHSecrets :: Cfg.Config -> QueueEntry -> IO Secrets
genSSHSecrets cfg qe = do
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
    return Secrets { key_secret = pw, key_file = fn }
