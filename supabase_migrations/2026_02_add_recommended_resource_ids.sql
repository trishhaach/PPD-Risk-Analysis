-- Migration: Add recommended_resource_ids column to epdsresult table
-- Run this in Supabase SQL Editor
-- Date: 2026-02-07
-- Description: Adds a text[] column to store IDs of recommended crisis resources for each screening

-- Add column to epdsresult table (used for both EPDS and Hybrid screenings)
ALTER TABLE epdsresult 
ADD COLUMN IF NOT EXISTS recommended_resource_ids text[];

-- Note: This column will be NULL for existing records and new screenings where
-- include_crisis_resources=false. It will contain an array of resource IDs when
-- crisis resources are requested and generated.


