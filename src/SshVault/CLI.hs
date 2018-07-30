{-#LANGUAGE ScopedTypeVariables#-}

module SshVault.CLI (cli)
    where

import Data.Semigroup ((<>))
import Options.Applicative

data Opts = Opts
    { optVerbose :: !Bool
    , optCommand :: !Command
    }

data Command
    = Create String
    | Delete
    | Init

cli :: IO ()
cli = do
    (opts :: Opts) <- execParser optsParser
    case optCommand opts of
        Create name -> putStrLn ("Created the thing named " ++ name)
        Delete -> putStrLn "Deleted the thing!"
        Init -> putStrLn "Init the thing!"
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
        hsubparser (createCommand <> deleteCommand <> initCommand)

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
            (info (pure Init) (progDesc "Init the thing"))