# app/report.py
from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel
from pymongo import MongoClient
from datetime import datetime
from typing import Optional
import csv
import io
from bson import ObjectId

router = APIRouter()

# Fixed: Use the same MongoDB connection URL as main.py (without trailing slash)
client = MongoClient("mongodb://localhost:27017")
db = client["PreTectNIDS"]
collection = db["detection_reports"]

# Report model for saving reports
class Report(BaseModel):
    model: str
    input: list[float]
    output: dict
    timestamp: str = datetime.utcnow().isoformat()

@router.post("/report")
def save_report(report: Report):
    try:
        collection.insert_one(report.dict())
        return {"message": "Report saved successfully"}
    except Exception as e:
        print(f"Error saving report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/reports")
def get_reports(
    limit: int = Query(100, description="Number of reports to return (max 500)"),
    skip: int = Query(0, description="Number of reports to skip"),
    model: Optional[str] = Query(None, description="Filter by model name"),
    status: Optional[str] = Query(None, description="Filter by prediction status (Attack/Normal)"),
    type: Optional[str] = Query(None, description="Filter by detection type (manual_testing/real_time_detection)"),
    interface: Optional[str] = Query(None, description="Filter by network interface"),
    date_from: Optional[str] = Query(None, description="Filter from date (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="Filter to date (YYYY-MM-DD)")
):
    try:
        print(f"Fetching reports with filters: limit={limit}, skip={skip}, model={model}, status={status}, type={type}, interface={interface}, date_from={date_from}, date_to={date_to}")
        
        # Validate and limit the parameters
        limit = min(max(1, limit), 500)  # Between 1 and 500
        skip = max(0, skip)  # At least 0
        
        # Build query filter
        query_filter = {}
        
        # Model filter
        if model:
            query_filter["model"] = model
        
        # Status filter - filter by prediction result
        if status:
            query_filter["result.prediction"] = status
        
        # Detection type filter
        if type:
            query_filter["type"] = type
        
        # Network interface filter
        if interface:
            query_filter["interface"] = interface
        
        # Date range filters
        date_query = {}
        if date_from:
            try:
                # Convert date to datetime for comparison
                from_date = datetime.strptime(date_from, "%Y-%m-%d")
                date_query["$gte"] = from_date.isoformat()
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date_from format. Use YYYY-MM-DD")
        
        if date_to:
            try:
                # Convert date to end of day for comparison
                to_date = datetime.strptime(date_to, "%Y-%m-%d")
                to_date = to_date.replace(hour=23, minute=59, second=59)
                date_query["$lte"] = to_date.isoformat()
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date_to format. Use YYYY-MM-DD")
        
        if date_query:
            query_filter["timestamp"] = date_query
        
        print(f"MongoDB query filter: {query_filter}")
        
        # Get reports with pagination, sorted by timestamp (newest first)
        reports = list(
            collection.find(query_filter, {"_id": 0})
            .sort("timestamp", -1)
            .skip(skip)
            .limit(limit)
        )
        
        # Get total count for pagination info
        total_count = collection.count_documents(query_filter)
        
        print(f"Found {len(reports)} reports (total: {total_count})")
        
        return {
            "reports": reports,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "skip": skip,
                "has_more": skip + limit < total_count
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/reports/stats")
def get_reports_stats():
    """Get statistics about reports in the database"""
    try:
        total = collection.count_documents({})
        
        # Get model distribution
        pipeline = [
            {"$group": {"_id": "$model", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        model_stats = list(collection.aggregate(pipeline))
        
        # Get status distribution
        status_pipeline = [
            {"$group": {"_id": "$result.prediction", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        status_stats = list(collection.aggregate(status_pipeline))
        
        # Get detection type distribution
        type_pipeline = [
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        type_stats = list(collection.aggregate(type_pipeline))
        
        # Get network interface distribution
        interface_pipeline = [
            {"$group": {"_id": "$interface", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        interface_stats = list(collection.aggregate(interface_pipeline))
        
        # Get recent activity (last 24 hours)
        from datetime import datetime, timedelta
        yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()
        recent_count = collection.count_documents({"timestamp": {"$gte": yesterday}})
        
        return {
            "total_reports": total,
            "recent_reports_24h": recent_count,
            "model_distribution": model_stats,
            "status_distribution": status_stats,
            "type_distribution": type_stats,
            "interface_distribution": interface_stats
        }
    except Exception as e:
        print(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/reports/export")
async def export_reports(
    request: Request,
    format: str = Query("csv", description="Export format (csv/json)"),
    model: Optional[str] = Query(None, description="Filter by model name"),
    status: Optional[str] = Query(None, description="Filter by prediction status"),
    type: Optional[str] = Query(None, description="Filter by detection type"),
    interface: Optional[str] = Query(None, description="Filter by network interface"),
    date_from: Optional[str] = Query(None, description="Filter from date"),
    date_to: Optional[str] = Query(None, description="Filter to date")
):
    """Export reports data (requires export_data permission)"""
    try:
        # Import here to avoid circular imports
        from app.auth import get_current_user_from_request, has_permission, get_default_role
        
        # Check permission
        user = await get_current_user_from_request(request)
        if not has_permission(user.get("role", get_default_role()), "export_data"):
            raise HTTPException(status_code=403, detail="Permission denied: export_data required")
        
        # Build query (same logic as get_reports)
        query = {}
        
        if model:
            query["result.model"] = {"$regex": model, "$options": "i"}
        
        if status:
            query["result.prediction"] = status
        
        if type:
            query["type"] = type
        
        if interface:
            query["interface"] = interface
        
        if date_from or date_to:
            date_query = {}
            if date_from:
                date_query["$gte"] = date_from
            if date_to:
                date_query["$lte"] = date_to + "T23:59:59"
            query["timestamp"] = date_query
        
        # Get all matching reports
        reports = list(collection.find(query).sort("timestamp", -1))
        
        if format.lower() == "csv":
            # Create CSV
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                "Timestamp", "Model", "Prediction", "Type", "Interface",
                "Anomaly Score", "Probability", "Features Count"
            ])
            
            # Write data
            for report in reports:
                writer.writerow([
                    report.get("timestamp", ""),
                    report.get("result", {}).get("model", ""),
                    report.get("result", {}).get("prediction", ""),
                    report.get("type", ""),
                    report.get("interface", ""),
                    report.get("result", {}).get("anomaly_score", ""),
                    report.get("result", {}).get("probability", ""),
                    len(report.get("features", []))
                ])
            
            csv_data = output.getvalue()
            output.close()
            
            return Response(
                content=csv_data,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=detection_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
            )
        
        else:  # JSON format
            # Convert ObjectId to string for JSON serialization
            for report in reports:
                if "_id" in report:
                    report["_id"] = str(report["_id"])
            
            import json
            json_data = json.dumps(reports, indent=2, default=str)
            
            return Response(
                content=json_data,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=detection_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"}
            )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error exporting reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/reports/{report_id}")
async def delete_report(report_id: str, request: Request):
    """Delete a specific report (requires delete_reports permission)"""
    try:
        # Import here to avoid circular imports
        from app.auth import get_current_user_from_request, has_permission, get_default_role
        
        # Check permission
        user = await get_current_user_from_request(request)
        if not has_permission(user.get("role", get_default_role()), "delete_reports"):
            raise HTTPException(status_code=403, detail="Permission denied: delete_reports required")
        
        # Delete report
        result = collection.delete_one({"_id": ObjectId(report_id)})
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Report not found")
        
        return {"message": "Report deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error deleting report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/reports/bulk")
async def bulk_delete_reports(request: Request, report_ids: dict):
    """Delete multiple reports (requires delete_reports permission)"""
    try:
        # Import here to avoid circular imports
        from app.auth import get_current_user_from_request, has_permission, get_default_role
        
        # Check permission
        user = await get_current_user_from_request(request)
        if not has_permission(user.get("role", get_default_role()), "delete_reports"):
            raise HTTPException(status_code=403, detail="Permission denied: delete_reports required")
        
        ids = report_ids.get("ids", [])
        if not ids:
            raise HTTPException(status_code=400, detail="No report IDs provided")
        
        # Convert string IDs to ObjectId
        object_ids = [ObjectId(id) for id in ids]
        
        # Delete reports
        result = collection.delete_many({"_id": {"$in": object_ids}})
        
        return {
            "message": f"Successfully deleted {result.deleted_count} reports",
            "deleted_count": result.deleted_count
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error bulk deleting reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))
