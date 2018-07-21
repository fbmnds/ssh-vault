module Main where

import Ssh (ssh)
import Turtle

main :: IO ExitCode
main = ssh
