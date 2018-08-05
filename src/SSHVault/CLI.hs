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

import qualified Data.Aeson as JSON



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
    | UploadSSHKey String String

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
        SSHAdd h u' -> sshAdd h u'
        UploadSSHKey h u' -> do
            cfg <- Cfg.genDefaultConfig
            m   <- getKeyPhrase
            (v :: Vault) <- decryptVault (toSBytes m) (Cfg.file cfg)
            user' <- case getUser v h u' of
                [u''] -> return u''
                _     -> error "vault inconsistent"
            newkey <- genSSHKey cfg m h user'
            print $ JSON.toJSON newkey
            print "\n"
            uploadSSHKey cfg m h user' newkey
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
                   <> initCommand
                   <> printCommand
                   <> b64encryptCommand
                   <> sshaddCommand
                   <> uploadSSHKeyCommand)

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
        strArgument (metavar "HOST" <> help "Target host for SSH key activation") <*>
        strArgument (metavar "USER" <> help "Target user for SSH key activation")

    uploadSSHKeyCommand :: Mod CommandFields Command
    uploadSSHKeyCommand =
        command
            "upload-sshkey"
            (info uploadSSHKeyOptions (progDesc "Upload SSH key for user@host"))
    uploadSSHKeyOptions :: Parser Command
    uploadSSHKeyOptions =
        UploadSSHKey <$>
        strArgument (metavar "HOST" <> help "Target host for SSH key upload") <*>
        strArgument (metavar "USER" <> help "Target user for SSH key upload")
