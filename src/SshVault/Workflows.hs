-- :set -XOverloadedStrings
{-# LANGUAGE OverloadedStrings #-}
module SshVault.Workflows 
    (
      uploadKeyCmd
    , genSSHFilename
    , chmodSSHFile
    , genSSHSecrets

    ) 
    where

import SshVault.Vault
import SshVault.SBytes
import SshVault.Common

import System.IO (appendFile)

import Data.Maybe (fromMaybe)
import Data.Text (Text, unpack)
import qualified Data.ByteArray as BA

import qualified Turtle as Tu
import           Turtle.Format 
import qualified Turtle.Prelude as Tu
import           Turtle.Line (lineToText)


uploadKeyCmd :: Text -> Text -> Text -> Text -> Text -> Text
uploadKeyCmd home newKeyFile currKeyFile user host = format (s % s % s) p1 p2 p3
    where
        p1 = format ("cat " % s % "/.ssh/" % s % ".pub") home newKeyFile
        p2 = format (" | ssh -i " % s % "/.ssh/" % s) home currKeyFile
        p3 =
            if user == "root" then 
                format (
                    " root@" % s % 
                    " \"cat >> /root/.ssh/authorized_keys\""
                    ) host  
            else 
                format (
                    " " % s % "@" % s % 
                    " \"cat >> /home/" % s % "/.ssh/authorized_keys\""
                    ) user host user


genSSHFilename :: Config -> QueueEntry -> IO Text
genSSHFilename cfg qe = do 
    date <- Tu.date
    let ud = format (s%w) (user $ snd qe) date
    let kn = toText . genSHA256 $ format (s %s) (fst qe) ud
    let fn = format (fp % s % s) (getCfgHome cfg) "/.ssh/id" kn
    return fn


chmodSSHFile :: Text -> IO ()
chmodSSHFile fn = procD "chmod" ["600", fn] Tu.empty


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

genSSHSecrets :: Config -> QueueEntry -> IO Secrets
genSSHSecrets cfg qe = do
    printf "[*] generate new SSH key password\n"
    passwd <- randS 20
    printf "[*] generate new SSH key file name\n"
    fn <- genSSHFilename cfg qe
    printf "[*] ssh-keygen new SSH key file\n"
    procD
        "ssh-keygen"
        [ "-n", user $ snd qe
        , "-t", "rsa"
        , "-b", "4096"
        , "-f", fn
        , "-P", passwd
        ]
        Tu.empty
    printf "[+] new SSH secrets generated"
    chmodSSHFile fn
    printf "[+] chmod 660 on new SSH file"
    return Secrets {key_secret=passwd, key_file=fn} 


