{-# LANGUAGE ScopedTypeVariables #-}

module SSHVault.Vault.Queue
  ( Queue
  , QueueEntry (..)
  , genQueue
  )
  where

import SSHVault.SBytes


data QueueEntry = UserUpdate (HostName, User) | HostUpdate VaultEntry
type Queue = [QueueEntry]



genQueue :: [VaultEntry] -> [QueueEntry]
genQueue = concatMap
  (\ve -> (\(h, us) -> map (\u' -> UserUpdate (h, u')) us) (host ve, users ve))
