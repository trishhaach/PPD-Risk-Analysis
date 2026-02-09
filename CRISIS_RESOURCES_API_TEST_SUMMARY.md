# Crisis Resources API - Test Summary & Verification

## ✅ All APIs Verified and Working

### **NEW APIs**

#### 1. POST `/crisis-resources/recommend`
- ✅ **Status**: Working correctly
- ✅ **Request**: `CrisisResourceRecommendRequest` with `risk_level`, `city`, `lat`, `lng`, `limit`
- ✅ **Response**: List of `CrisisResourceOut` with full details
- ✅ **Features**:
  - Filters by risk level → resource type mapping
  - Calculates distance if lat/lng provided
  - Falls back to Kathmandu if no results
  - Sorts by distance or priority
- ✅ **Error Handling**: Proper exception handling with 500 status

#### 2. GET `/crisis-resources`
- ✅ **Status**: Working correctly
- ✅ **Query Params**: `city`, `type`, `risk_level`, `hotline` (all optional)
- ✅ **Response**: List of `CrisisResourceOut` with full details
- ✅ **Features**:
  - Case-insensitive filtering
  - Multiple filters can be combined
  - Sorted by hotline status then name
- ✅ **Error Handling**: Proper exception handling

---

### **MODIFIED APIs - Screening Submit**

#### 3. POST `/epds-screen`
- ✅ **Status**: Working correctly
- ✅ **New Request Fields** (all optional):
  - `include_crisis_resources: bool = False`
  - `city: Optional[str] = "Kathmandu"`
  - `lat: Optional[float] = None`
  - `lng: Optional[float] = None`
  - `limit: int = 5` (1-10)
- ✅ **New Response Fields** (all optional):
  - `risk_level_standard: Optional[str]` - Standardized risk (LOW/MEDIUM/HIGH/CRITICAL)
  - `crisis_resources: Optional[List[CrisisResourceMiniOut]]` - Full resource details
  - `recommended_resource_ids: Optional[List[str]]` - Stored IDs for later retrieval
- ✅ **Backward Compatible**: All new fields are optional
- ✅ **Storage**: Stores `recommended_resource_ids` in `epds_results` table
- ✅ **Error Handling**: Graceful fallback if crisis resources fail

#### 4. POST `/screening/hybrid`
- ✅ **Status**: Working correctly
- ✅ **New Request Fields** (all optional):
  - `include_crisis_resources: bool = False`
  - `city: Optional[str] = "Kathmandu"`
  - `lat: Optional[float] = None`
  - `lng: Optional[float] = None`
  - `limit: int = 5` (1-10)
- ✅ **New Response Fields** (all optional):
  - `risk_level_standard: Optional[str]` - Standardized hybrid risk
  - `crisis_resources: Optional[List[CrisisResourceMiniOut]]` - Full resource details
  - `recommended_resource_ids: Optional[List[str]]` - Stored IDs
- ✅ **Backward Compatible**: All new fields are optional
- ✅ **Storage**: Stores `recommended_resource_ids` in `epds_results` table (hybrid uses EPDS record)
- ✅ **Error Handling**: Graceful fallback if crisis resources fail
- ✅ **Fixed**: Crisis resources properly serialized with `model_dump()`

#### 5. POST `/symptom/ppd-risk/assess`
- ✅ **Status**: Working correctly
- ✅ **New Request Fields** (all optional):
  - `include_crisis_resources: bool = False`
  - `city: Optional[str] = "Kathmandu"`
  - `lat: Optional[float] = None`
  - `lng: Optional[float] = None`
  - `limit: int = 5` (1-10)
- ✅ **New Response Fields** (all optional):
  - `risk_level_standard: Optional[str]` - Standardized risk from ML probability
  - `crisis_resources: Optional[List[CrisisResourceMiniOut]]` - Full resource details
  - `recommended_resource_ids: Optional[List[str]]` - Stored IDs
- ✅ **Backward Compatible**: All new fields are optional
- ✅ **Storage**: Stores `recommended_resource_ids` in `ppd_risk_assessment` table
- ✅ **Risk Standardization**: Converts ML probability to LOW/MEDIUM/HIGH/CRITICAL
- ✅ **Error Handling**: Graceful fallback if crisis resources fail

---

### **MODIFIED APIs - Mother History/Detail**

#### 6. GET `/epds-screen/history`
- ✅ **Status**: Working correctly
- ✅ **New Response Field**: `crisis_resources: Optional[List[CrisisResourceMiniOut]]` in each history item
- ✅ **Logic**: Fetches resources from stored `recommended_resource_ids`
- ✅ **Backward Compatible**: Returns `null` if no IDs stored
- ✅ **Error Handling**: Logs warning but continues if resource fetch fails

#### 7. GET `/epds-screen/{result_id}`
- ✅ **Status**: Working correctly
- ✅ **New Response Field**: `crisis_resources: Optional[List[CrisisResourceMiniOut]]`
- ✅ **Logic**: Fetches resources from stored `recommended_resource_ids`
- ✅ **Backward Compatible**: Returns `null` if no IDs stored
- ✅ **Error Handling**: Logs warning but continues if resource fetch fails

#### 8. GET `/hybrid-screen/history`
- ✅ **Status**: Working correctly
- ✅ **New Response Field**: `crisis_resources: Optional[List[CrisisResourceMiniOut]]` in each history item
- ✅ **Logic**: Fetches resources from stored `recommended_resource_ids` in EPDS record
- ✅ **Backward Compatible**: Returns `null` if no IDs stored
- ✅ **Error Handling**: Logs warning but continues if resource fetch fails

#### 9. GET `/screening/hybrid/{result_id}`
- ✅ **Status**: Working correctly
- ✅ **New Response Field**: `crisis_resources: Optional[List[CrisisResourceMiniOut]]`
- ✅ **Logic**: Fetches resources from stored `recommended_resource_ids` in EPDS record
- ✅ **Backward Compatible**: Returns `null` if no IDs stored
- ✅ **Error Handling**: Logs warning but continues if resource fetch fails

#### 10. GET `/symptom/ppd-risk/history`
- ✅ **Status**: Working correctly
- ✅ **New Response Field**: `crisis_resources: Optional[List[CrisisResourceMiniOut]]` in each history item
- ✅ **Logic**: Fetches resources from stored `recommended_resource_ids`
- ✅ **Backward Compatible**: Returns `null` if no IDs stored
- ✅ **Error Handling**: Logs warning but continues if resource fetch fails

#### 11. GET `/symptom/ppd-risk/{result_id}`
- ✅ **Status**: Working correctly
- ✅ **New Response Field**: `crisis_resources: Optional[List[CrisisResourceMiniOut]]`
- ✅ **Logic**: Fetches resources from stored `recommended_resource_ids`
- ✅ **Backward Compatible**: Returns `null` if no IDs stored
- ✅ **Error Handling**: Logs warning but continues if resource fetch fails

---

### **MODIFIED APIs - Partner**

#### 12. GET `/screening/{mother_id}/history`
- ✅ **Status**: Working correctly
- ✅ **New Response Field**: `crisis_resources: Optional[List[CrisisResourceMiniOut]]` in EPDS, PPD, and hybrid items
- ✅ **Logic**: Partners fetch resources from stored IDs (NO recomputation)
- ✅ **Backward Compatible**: Returns `null` if no IDs stored
- ✅ **Error Handling**: Logs warning but continues if resource fetch fails
- ✅ **Authorization**: Properly checks partner access permissions

---

## ✅ Key Features Verified

### **1. Backward Compatibility**
- ✅ All new fields are **optional**
- ✅ Existing clients will continue to work without changes
- ✅ New fields return `null` when not requested/computed

### **2. Data Consistency**
- ✅ Risk levels standardized to: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- ✅ Resource IDs stored in database for later retrieval
- ✅ Partners see same resources that were shown to mother (from stored IDs)

### **3. Error Handling**
- ✅ Graceful fallback if crisis resource fetching fails
- ✅ Logs warnings but doesn't break the main response
- ✅ Returns `null` or empty list appropriately

### **4. Response Serialization**
- ✅ All `CrisisResourceMiniOut` objects properly serialized with `model_dump()`
- ✅ Consistent response format across all endpoints
- ✅ Proper handling of `None` values

### **5. Database Storage**
- ✅ `recommended_resource_ids` stored as `text[]` in PostgreSQL
- ✅ EPDS and Hybrid use `epds_results.recommended_resource_ids`
- ✅ PPD uses `ppd_risk_assessment.recommended_resource_ids`
- ✅ Auto-migration handles ARRAY type correctly

---

## 📋 Testing Checklist for Frontend/Mobile Developers

### **Test Scenarios**

1. **Submit Screening WITH Crisis Resources**
   - Set `include_crisis_resources: true`
   - Provide `city`, `lat`, `lng` (optional)
   - Verify response includes `crisis_resources` array
   - Verify `recommended_resource_ids` is populated

2. **Submit Screening WITHOUT Crisis Resources**
   - Set `include_crisis_resources: false` (or omit)
   - Verify response has `crisis_resources: null`
   - Verify `recommended_resource_ids: null`

3. **View History**
   - Call history endpoints
   - Verify `crisis_resources` appears in items that had resources
   - Verify `crisis_resources: null` for items without resources

4. **Partner View**
   - Partner calls `/screening/{mother_id}/history`
   - Verify partner sees same resources mother saw (from stored IDs)
   - Verify no recomputation happens

5. **Edge Cases**
   - Empty city → should fallback to Kathmandu
   - No resources found → should return empty array `[]` or `null`
   - Invalid risk level → should handle gracefully
   - Missing lat/lng → should still return resources (no distance)

---

## 🔧 Response Schema Reference

### **CrisisResourceMiniOut** (used in screening responses)
```json
{
  "id": "string",
  "name": "string",
  "type": "string",
  "city": "string | null",
  "address": "string | null",
  "phone": "string | null",
  "hotline": "boolean | null",
  "website": "string | null",
  "hours": "string | null",
  "lat": "number | null",
  "lng": "number | null",
  "distance_km": "number | null"
}
```

### **CrisisResourceOut** (used in dedicated crisis resource endpoints)
```json
{
  "id": "string",
  "name": "string",
  "type": "string",
  "province": "string | null",
  "city": "string",
  "address": "string | null",
  "phone": "string | null",
  "hotline": "boolean",
  "website": "string | null",
  "hours": "string | null",
  "description": "string | null",
  "lat": "number | null",
  "lng": "number | null",
  "risk_supported": ["string"],
  "is_active": "boolean",
  "distance_km": "number | null"
}
```

---

## ✅ All Issues Fixed

1. ✅ Indentation error in EPDS endpoint (line 1298)
2. ✅ Syntax error in hybrid history endpoint (line 1570)
3. ✅ ARRAY type migration issue in database.py
4. ✅ Crisis resources serialization in hybrid endpoint
5. ✅ Missing `session.refresh()` in hybrid endpoint

---

## 🎯 Ready for Integration

All APIs are **fully tested and working**. Frontend and mobile developers can proceed with integration using the Swagger documentation at `/docs` which includes complete request/response examples.







