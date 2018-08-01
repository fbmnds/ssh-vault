{-#LANGUAGE ScopedTypeVariables#-}

module SSHVault.CLI (cli)
    where

import Data.Semigroup ((<>))
import Options.Applicative

import SSHVault.Vault.Config
import SSHVault.Workflows

data Opts = Opts
    { optVerbose :: !Bool
    , optCommand :: !Command
    }

data Command
    = Create String
    | Delete
    | Init
    | Print String

cli :: IO ()
cli = do
    (opts :: Opts) <- execParser optsParser
    case optCommand opts of
        Create name -> putStrLn ("Created the thing named " ++ name)
        Delete -> putStrLn "Deleted the thing!"
        Init -> initVault
        Print _ -> do
            cfg <- genDefaultConfig
            printVault cfg
    putStrLn ("verbosity: " ++ show (optVerbose opts))
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
        hsubparser (createCommand <> deleteCommand <> initCommand <> printCommand)

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
            (info printOptions (progDesc "Print the vault"))
    printOptions :: Parser Command
    printOptions =
        Print <$>
        strArgument (metavar "CONFIG" <> help "Vault configuration to use for printing")
