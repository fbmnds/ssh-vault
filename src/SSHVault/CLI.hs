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
--import System.Process
--import Foreign.C.String
--import Control.Monad


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
    | RotateUserSSHKey String String



cli :: IO ()
cli =
    do
        --principal <- newCString "root"
        --when (g_auth principal == 1) $ error "not authenticated"
        cfg <- Cfg.genDefaultConfig
        (opts :: Opts) <- execParser optsParser
        case optCommand opts of
            Insert s'         -> do
                m <- getAESMasterKeyU
                WF.insertSSHKey WF.Insert cfg m s'
            Replace s'        -> do
                m <- getAESMasterKeyU
                WF.insertSSHKey WF.Replace cfg m s'
            Init              -> WF.initVault cfg
            Print             -> WF.printVault cfg
            B64Encrypt        -> WF.b64EncryptSSHKeyPassphrase
            SSHAdd h u'       -> do
                m <- getAESMasterKeyU
                WF.sshAdd cfg m h u'
            RotateUserSSHKey h u' -> do
                m <- getAESMasterKeyU
                withFile "/dev/shm/log" AppendMode $ \ hnd -> do
                    hDuplicateTo hnd stderr
                    WF.rotateUserSSHKey cfg m h u'
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
                   <> rotateUserSSHKeyCommand)

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

    rotateUserSSHKeyCommand :: Mod CommandFields Command
    rotateUserSSHKeyCommand =
        command
            "rotate-user-sshkey"
            (info rotateUserSSHKeyOptions (progDesc "Generate and upload new SSH key for user@host"))
    rotateUserSSHKeyOptions :: Parser Command
    rotateUserSSHKeyOptions =
        RotateUserSSHKey <$>
        strArgument (metavar "HOST" <> help "Target host for single user's SSH key rotation") <*>
        strArgument (metavar "USER" <> help "Target user for single user's SSH key rotation")
