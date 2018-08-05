{-#LANGUAGE ScopedTypeVariables#-}

module SSHVault.CLI (cli)
    where

import Data.Semigroup ((<>))
import Options.Applicative

import SSHVault.Common
import SSHVault.Vault
import qualified SSHVault.Vault.Config as Cfg
import SSHVault.Workflows
import SSHVault.SBytes

import           Data.Maybe (fromMaybe)
import qualified Data.Aeson as JSON
import qualified Data.ByteString.Base64 as B64


--import System.IO


data Opts = Opts
    {   optVerbose :: !Bool
      , optCommand :: !Command
    }

data Command
    = Insert String
    | Init
    | Print
    | B64Encrypt
    | SSHAdd String String

cli :: IO ()
cli = do
    (opts :: Opts) <- execParser optsParser
    case optCommand opts of
        Insert s' -> do
            cfg <- Cfg.genDefaultConfig
            m   <- getKeyPhrase
            insertSSHKey cfg m s'
        Init -> do
            cfg <- Cfg.genDefaultConfig
            initVault cfg
        Print -> do
            cfg <- Cfg.genDefaultConfig
            printVault cfg
        B64Encrypt -> b64EncryptSSHKeyPassphrase
        SSHAdd h u -> sshAdd h u
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
        hsubparser (insertCommand <> initCommand <> printCommand <> b64encryptCommand <> sshaddCommand)

    insertCommand :: Mod CommandFields Command
    insertCommand =
        command
            "insert"
            (info insertOptions (progDesc "Insert a vault entry"))
    insertOptions :: Parser Command
    insertOptions =
        Insert <$>
        strArgument (metavar "VAULTENTRY" <> help "JSON formatted vault entry to insert")

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
        strArgument (metavar "HOST" <> help "Target host for SSH Key") <*>
        strArgument (metavar "USER" <> help "Target user for SSH Key")