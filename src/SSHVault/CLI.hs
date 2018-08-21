{-#LANGUAGE ScopedTypeVariables#-}

module SSHVault.CLI (cli)
    where

import SSHVault.Common
import SSHVault.SBytes
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
    | SSHAdd HostName UserName
    | RotateUserSSHKey HostName UserName
    | PurgeUserSSHKeys HostName UserName



cli :: IO ()
cli =
    do
        --principal <- newCString "root"
        --when (g_auth principal == 1) $ error "not authenticated"
        cfg <- Cfg.genDefaultConfig
        (opts :: Opts) <- execParser optsParser
        case optCommand opts of
            Init       -> WF.initVault cfg
            Print      -> WF.printVault cfg
            B64Encrypt -> WF.b64EncryptSSHKeyPassphrase
            Insert s' -> do
                m <- getAESMasterKeyU
                WF.insertSSHKey WF.Insert cfg m s'
            Replace s' -> do
                m <- getAESMasterKeyU
                WF.insertSSHKey WF.Replace cfg m s'
            SSHAdd h un -> do
                m <- getAESMasterKeyU
                WF.sshAdd cfg m h un
            RotateUserSSHKey h un -> do
                m <- getAESMasterKeyU
                withFile "/dev/shm/log" AppendMode $ \ hnd -> do
                    hDuplicateTo hnd stderr
                    WF.rotateUserSSHKey cfg m h un
            PurgeUserSSHKeys h un -> do
                m <- getAESMasterKeyU
                WF.purgeUserSSHKeys cfg m h un


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
                   <> rotateUserSSHKeyCommand
                   <> purgeUserSSHKeysCommand)

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
            "rotate-key"
            (info rotateUserSSHKeyOptions (progDesc "Generate and upload new SSH key for user@host"))
    rotateUserSSHKeyOptions :: Parser Command
    rotateUserSSHKeyOptions =
        RotateUserSSHKey <$>
        strArgument (metavar "HOST" <> help "Target host for single user's SSH key rotation") <*>
        strArgument (metavar "USER" <> help "Target user for single user's SSH key rotation")

    purgeUserSSHKeysCommand :: Mod CommandFields Command
    purgeUserSSHKeysCommand =
        command
            "purge-keys"
            (info purgeUserSSHKeysOptions (progDesc "Purge unused SSH keys for user@host"))
    purgeUserSSHKeysOptions :: Parser Command
    purgeUserSSHKeysOptions =
        PurgeUserSSHKeys <$>
        strArgument (metavar "HOST" <> help "Target host for single user's SSH key purge") <*>
        strArgument (metavar "USER" <> help "Target user for single user's SSH key purge")
