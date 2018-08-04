{-#LANGUAGE ScopedTypeVariables#-}

module SSHVault.CLI (cli)
    where

import Data.Semigroup ((<>))
import Options.Applicative

import SSHVault.Common
import SSHVault.Vault
import SSHVault.Vault.Config
import SSHVault.Workflows
import SSHVault.SBytes

import           Data.Maybe (fromMaybe)
import qualified Data.Aeson as JSON
import qualified Data.ByteString.Base64 as B64


import System.IO


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
            (ve :: VaultEntry) <- return . fromMaybe (error "failed to JSON.decode the given input") . JSON.decode $ toLUBytes s'
            cfg <- genDefaultConfig
            m <- getKeyPhrase
            (v :: Vault) <- decryptVault m (file cfg)
            case filter (\ h ->  h == host ve) $ fmap host (vault v) of
                [] -> encryptVault (toSBytes m) (file cfg) (Vault (vault v ++ [ve]))
                _ -> error $ "failed to insert host " ++ host ve ++ ": already in vault"
        Init -> initVault
        Print -> do
            cfg <- genDefaultConfig
            printVault cfg
        B64Encrypt ->  do
            putStrLn "1. Masterpassword"
            m <- getKeyPhrase
            print m
            putStrLn "2. SSH key"
            k <- getLine
            print k
            aesk <- encryptAES m $ toBytes k
            let b64aesk = B64.encode aesk
            print b64aesk
            case B64.decode b64aesk of
                Left e -> print e
                Right x -> do
                    y <- decryptAES m x
                    print y
        SSHAdd h u -> sshAdd h u
  -- ssh-add " ++ key_file u ++ "; interact }'"]


-- expect -c 'expect "\n" { eval spawn ssh -oStrictHostKeyChecking=no -oCheckHostIP=no usr@$myhost.example.com; interact }'


    -- putStrLn ("verbosity: " ++ show (optVerbose opts))
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
            (info (pure B64Encrypt) (progDesc "Encrypt and b64encode a phrase by password"))

    sshaddCommand :: Mod CommandFields Command
    sshaddCommand =
        command
            "ssh-add"
            (info sshaddOptions (progDesc "Activate SSH key \"host:user\""))
    sshaddOptions :: Parser Command
    sshaddOptions =
        SSHAdd <$>
        strArgument (metavar "HOST" <> help "Target host for SSH Key") <*>
        strArgument (metavar "USER" <> help "Target user for SSH Key")