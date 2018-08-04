{-# LANGUAGE ScopedTypeVariables #-}

module SSHVault.Vault.Queue
  ( Queue
  , QueueEntry (..)
  , genQueue
  )
  where

import SSHVault.Vault


data QueueEntry = UserUpdate (Host, [User]) | HostUpdate VaultEntry
type Queue = [QueueEntry]



genQueue :: [VaultEntry] -> [QueueEntry]
genQueue = map (\ ve -> UserUpdate (host ve, users ve))


