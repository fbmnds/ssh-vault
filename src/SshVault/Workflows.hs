-- :set -XOverloadedStrings
{-# LANGUAGE OverloadedStrings #-}
module SshVault.Workflows 
    (
      ssh
    , uploadKey
    ) 
    where

import System.Environment (lookupEnv)
import System.IO (appendFile)

import Data.Maybe (fromMaybe)
import Data.Text (Text, unpack)

import Turtle (ExitCode, die, fromString, format, liftIO, readline, shell, empty, proc)
import Turtle.Format 
    (
--        Format 
      printf
    , (%)
    , s
    )
import Turtle.Line (lineToText)
  

uploadKey :: Text -> Text -> Text -> Text -> Text -> Text
uploadKey hm newKey currKey id' box = format (s % s% s) p1 p2 p3
    where
        p1 = format ("cat " % s % "/.ssh/" % s % ".pub") hm newKey
        p2 = format (" | ssh -i " % s % "/.ssh/" % s) hm currKey
        p3 =
            if id' == "root" then 
                format (
                    " root@" % s % 
                    " \"cat >> /root/.ssh/authorized_keys\""
                    ) box  
            else 
                format (
                    " " % s % "@" % s % 
                    " \"cat >> /home/" % s % "/.ssh/authorized_keys\""
                    ) id' box id'


ssh :: IO ExitCode
ssh = do
    let newKey  = "NEWKEY"
    let currKey = "id_rsa2048"
    let id'     = "root"
    let vault   = "ssh-vault"
    let box     = "fun"

    hm' <- lookupEnv "HOME" 
    let hm'' = fromMaybe "" hm' in
        if hm'' == "" then
            die "[-] $HOME not set"
        else do
            let hm = fromString hm''
            printf ("[+] $HOME=" % s % "\n") hm

            printf "[?] enter password > "
            passw' <- liftIO readline
            let passwd = case passw' of
                   Nothing -> ""
                   Just s' -> lineToText s'
            _ <- appendFile
                    (hm'' ++ "/.ssh/" ++ vault)
                    (unpack box ++ " : " ++ unpack passwd)

            printf "[*] purge previous key\n"
            _ <- shell 
                    (format ("rm " % s % "/.ssh/" % s % "*") hm newKey)
                    empty

            printf "[*] generate new key\n"
            _ <- proc
                "ssh-keygen"
                [ "-n", id'
                , "-t", "rsa"
                , "-b", "4096"
                , "-f", format (s % "/.ssh/" % s) hm newKey
                , "-P", passwd
                ]
                empty

            printf "[*] upload new key\n"
            shell (uploadKey hm newKey currKey id' box) empty
