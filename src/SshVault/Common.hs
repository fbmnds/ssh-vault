{-# LANGUAGE OverloadedStrings #-}
module SshVault.Common where

import qualified Data.ByteString.Char8 as BS
import Control.Exception(bracket_)

import System.IO


getKeyPhrase :: IO BS.ByteString
getKeyPhrase = do
  old <- hGetEcho stdin
  keyPhrase <- bracket_ 
         (hSetEcho stdin True) 
         (hSetEcho stdin old) 
         (do
              putStr "Encryption key phrase: "
              hFlush stdout
              hSetEcho stdin False
              keyPhrase <- getLine
              putChar '\n'
              putStr keyPhrase
              putChar '\n'
              return keyPhrase
        )
  return (BS.pack keyPhrase)


