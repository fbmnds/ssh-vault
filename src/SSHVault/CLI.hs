{-#LANGUAGE ScopedTypeVariables#-}

module SSHVault.CLI (cli)
    where

import SSHVault.Common
import qualified SSHVault.Vault.Config as Cfg
import qualified SSHVault.Workflows as WF

import Data.Semigroup ((<>))
import Options.Applicative
import GHC.IO.Handle
import System.IO
import Control.Exception

data Opts = Opts
    {   optVerbose :: !Bool
      , optCommand :: !Command
    }

data Command
    = Insert String
    | Replace String
    | Init
    | Print
    | B64Encrypt
    | SSHAdd String String
    | RotateSSHKey String String



cli :: IO ()
cli =
    withFile "/dev/shm/log" AppendMode $ \ hnd -> do
        hDuplicateTo hnd stderr
    --do
        (opts :: Opts) <- execParser optsParser
        case optCommand opts of
            Insert s' -> do
                cfg <- Cfg.genDefaultConfig
                m   <- getKeyPhrase
                WF.insertSSHKey WF.Insert cfg m s'
            Replace s' -> do
                cfg <- Cfg.genDefaultConfig
                m   <- getKeyPhrase
                WF.insertSSHKey WF.Replace cfg m s'
            Init -> do
                cfg <- Cfg.genDefaultConfig
                WF.initVault cfg
            Print -> do
                cfg <- Cfg.genDefaultConfig
                WF.printVault cfg
            B64Encrypt -> WF.b64EncryptSSHKeyPassphrase
            SSHAdd h u' -> WF.sshAdd h u'
            RotateSSHKey h u' -> do
                cfg <- Cfg.genDefaultConfig
                m   <- getKeyPhrase
                WF.rotateSSHKey cfg m h u'
  where
    optsParser :: ParserInfo Opts
    optsParser =
        info
            (helper <*> versionOption <*> programOptions)
            (fullDesc <> progDesc "SSH key management automation" <>
             header
                 "ssh-vault - SSH key management command line interface")

    versionOption :: Parser (a -> a)
    versionOption = infoOption "0.0.1" (long "version" <> help "Show version")

    programOptions :: Parser Opts
    programOptions =
        Opts <$> switch (long "verbose" <> short 'v' <> help "Toggle verbosity") <*>
        hsubparser (  insertCommand
                   <> replaceCommand
                   <> initCommand
                   <> printCommand
                   <> b64encryptCommand
                   <> sshaddCommand
                   <> rotateSSHKeyCommand)

    insertCommand :: Mod CommandFields Command
    insertCommand =
        command
            "insert"
            (info insertOptions (progDesc "Insert a vault entry"))
    insertOptions :: Parser Command
    insertOptions =
        SSHVault.CLI.Insert <$>
        strArgument (metavar "VAULTENTRY" <> help "JSON formatted vault entry to insert")

    replaceCommand :: Mod CommandFields Command
    replaceCommand =
        command
            "replace"
            (info replaceOptions (progDesc "replace a vault entry"))
    replaceOptions :: Parser Command
    replaceOptions =
        Replace <$>
        strArgument (metavar "VAULTENTRY" <> help "JSON formatted vault entry for replacement")


    initCommand :: Mod CommandFields Command
    initCommand =
        command
            "init"
            (info (pure Init) (progDesc "Init the vault"))

    printCommand :: Mod CommandFields Command
    printCommand =
        command
            "print"
            (info (pure Print) (progDesc "Print the vault"))

    b64encryptCommand :: Mod CommandFields Command
    b64encryptCommand =
        command
            "b64encrypt"
            (info (pure B64Encrypt) (progDesc "Encrypt and b64encode a SSH key passphrase"))

    sshaddCommand :: Mod CommandFields Command
    sshaddCommand =
        command
            "ssh-add"
            (info sshaddOptions (progDesc "Activate SSH key for user@host"))
    sshaddOptions :: Parser Command
    sshaddOptions =
        SSHAdd <$>
        strArgument (metavar "HOST" <> help "Target host for SSH key activation") <*>
        strArgument (metavar "USER" <> help "Target user for SSH key activation")

    rotateSSHKeyCommand :: Mod CommandFields Command
    rotateSSHKeyCommand =
        command
            "rotate-sshkey"
            (info rotateSSHKeyOptions (progDesc "Generate and upload new SSH key for user@host"))
    rotateSSHKeyOptions :: Parser Command
    rotateSSHKeyOptions =
        RotateSSHKey <$>
        strArgument (metavar "HOST" <> help "Target host for SSH key rotation") <*>
        strArgument (metavar "USER" <> help "Target user for SSH key rotation")
