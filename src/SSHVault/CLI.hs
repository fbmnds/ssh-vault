{-#LANGUAGE ScopedTypeVariables#-}

module SSHVault.CLI (cli)
    where

import Data.Semigroup ((<>))
import Options.Applicative

import SSHVault.Common
import SSHVault.Vault.Config
import SSHVault.Workflows
import SSHVault.SBytes

import qualified Data.ByteString.Base64 as B64
import System.IO

data Opts = Opts
    { optVerbose :: !Bool
    , optCommand :: !Command
    }

data Command
    = Create String
    | Delete
    | Init
    | Print
    | B64Encrypt

cli :: IO ()
cli = do
    (opts :: Opts) <- execParser optsParser
    case optCommand opts of
        Create name -> putStrLn ("Created the thing named " ++ name)
        Delete -> putStrLn "Deleted the thing!"
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
            daesk <- case B64.decode b64aesk of
                Left e -> print e
                Right x -> do
                    y <- decryptAES m x
                    print y
            return ()
    -- putStrLn ("verbosity: " ++ show (optVerbose opts))
  where
    optsParser :: ParserInfo Opts
    optsParser =
        info
            (helper <*> versionOption <*> programOptions)
            (fullDesc <> progDesc "optparse subcommands example" <>
             header
                 "optparse-sub-example - a small example program for optparse-applicative with subcommands")

    versionOption :: Parser (a -> a)
    versionOption = infoOption "0.0.1" (long "version" <> help "Show version")

    programOptions :: Parser Opts
    programOptions =
        Opts <$> switch (long "verbose" <> short 'v' <> help "Toggle verbosity") <*>
        hsubparser (createCommand <> deleteCommand <> initCommand <> printCommand <> b64encryptCommand)

    createCommand :: Mod CommandFields Command
    createCommand =
        command
            "create"
            (info createOptions (progDesc "Create a thing"))
    createOptions :: Parser Command
    createOptions =
        Create <$>
        strArgument (metavar "NAME" <> help "Name of the thing to create")

    deleteCommand :: Mod CommandFields Command
    deleteCommand =
        command
            "delete"
            (info (pure Delete) (progDesc "Delete the thing"))

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
