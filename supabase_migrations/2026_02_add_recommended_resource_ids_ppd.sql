-- Migration: Add recommended_resource_ids column to ppd_risk_assessment table
-- Run this in Supabase SQL Editor
-- Date: 2026-02-07
-- Description: Adds a text[] column to store IDs of recommended crisis resources for symptom-based PPD risk assessments

-- Add column to ppd_risk_assessment table
ALTER TABLE ppd_risk_assessment 
ADD COLUMN IF NOT EXISTS recommended_resource_ids text[];

-- Note: This column will be NULL for existing records and new assessments where
-- include_crisis_resources=false. It will contain an array of resource IDs when
-- crisis resources are requested and generated.

