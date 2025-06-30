from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import FileResponse
from typing import List, Dict, Any, Optional
from datetime import datetime
import os

# Import authentication module
from auth.auth_handler import get_current_active_user, User

# Import enhanced activity logger
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from activity_logger_enhanced import (
    log_activity,
    log_meta_activity,
    get_activities,
    verify_activity_integrity,
    create_lock_period,
    get_lock_periods,
    secure_export_activities,
    verify_export
)

# Create router
router = APIRouter(
    prefix="/api/logs",
    tags=["logs"],
    responses={404: {"description": "Not found"}},
)


# Models
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class LockPeriodCreate(BaseModel):
    """Request model for creating a lock period"""
    start_date: datetime = Field(..., description="Start date for the lock period")
    end_date: datetime = Field(..., description="End date for the lock period")
    reason: str = Field(..., description="Reason for the lock")


class LogFilter(BaseModel):
    """Request model for filtering logs"""
    user_id: Optional[str] = None
    activity_type: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    request_id: Optional[str] = None
    include_locked: Optional[bool] = False


class ExportRequest(BaseModel):
    """Request model for exporting logs"""
    filters: LogFilter
    format: str = Field("json", description="Export format: json or csv")


@router.get("/activities", response_model=List[Dict[str, Any]])
async def get_activities_endpoint(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user_id: Optional[str] = None,
    activity_type: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    request_id: Optional[str] = None,
    include_locked: bool = False,
    current_user: User = Depends(get_current_active_user),
    request: Request = None
):
    """Get activity logs with optional filtering"""
    # Extract IP address
    ip_address = request.client.host if request else None
    
    # Construct filter dictionary
    filters = {
        "user_id": user_id,
        "activity_type": activity_type,
        "start_date": start_date.isoformat() if start_date else None,
        "end_date": end_date.isoformat() if end_date else None,
        "request_id": request_id,
        "include_locked": include_locked
    }
    
    # Only remove None values, keep False values
    filters = {k: v for k, v in filters.items() if v is not None}
    
    # Get activities
    activities = get_activities(
        limit=limit,
        offset=offset,
        filters=filters,
        current_user=current_user,
        ip_address=ip_address
    )
    
    return activities


@router.get("/activities/{activity_id}/verify", response_model=Dict[str, Any])
async def verify_activity_endpoint(
    activity_id: int,
    current_user: User = Depends(get_current_active_user),
    request: Request = None
):
    """Verify the integrity and signature of an activity log"""
    ip_address = request.client.host if request else None
    
    result = verify_activity_integrity(
        activity_id=activity_id,
        current_user=current_user,
        ip_address=ip_address
    )
    
    return result


@router.post("/locks", status_code=status.HTTP_201_CREATED, response_model=Dict[str, Any])
async def create_lock_period_endpoint(
    lock_data: LockPeriodCreate,
    current_user: User = Depends(get_current_active_user),
    request: Request = None
):
    """Create a lock period for logs - requires admin privileges"""
    # Check if user is admin
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create log lock periods"
        )
    
    ip_address = request.client.host if request else None
    
    lock_id = create_lock_period(
        start_date=lock_data.start_date,
        end_date=lock_data.end_date,
        reason=lock_data.reason,
        locked_by=current_user.user_id,
        ip_address=ip_address,
        current_user=current_user
    )
    
    return {"lock_id": lock_id, "message": "Lock period created successfully"}


@router.get("/locks", response_model=List[Dict[str, Any]])
async def get_lock_periods_endpoint(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_active_user),
    request: Request = None
):
    """Get list of log lock periods"""
    ip_address = request.client.host if request else None
    
    lock_periods = get_lock_periods(
        limit=limit,
        offset=offset,
        current_user=current_user,
        ip_address=ip_address
    )
    
    return lock_periods


@router.post("/export", response_model=Dict[str, Any])
async def export_logs_endpoint(
    export_request: ExportRequest,
    current_user: User = Depends(get_current_active_user),
    request: Request = None
):
    """Securely export activity logs with verification"""
    ip_address = request.client.host if request else None
    
    # Convert Pydantic model to dict
    filters = export_request.filters.dict(exclude_none=True)
    
    # Convert datetime objects to ISO format strings
    if "start_date" in filters and filters["start_date"]:
        filters["start_date"] = filters["start_date"].isoformat()
    
    if "end_date" in filters and filters["end_date"]:
        filters["end_date"] = filters["end_date"].isoformat()
    
    export_result = secure_export_activities(
        filters=filters,
        export_format=export_request.format,
        current_user=current_user,
        ip_address=ip_address
    )
    
    # Return export metadata
    return export_result


@router.get("/export/{export_id}", response_class=FileResponse)
async def download_export_endpoint(
    export_id: str,
    current_user: User = Depends(get_current_active_user),
    request: Request = None
):
    """Download a previously generated export file"""
    exports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "exports")
    
    # Find export file by ID
    for filename in os.listdir(exports_dir):
        if export_id in filename and not filename.endswith(".meta"):
            file_path = os.path.join(exports_dir, filename)
            
            # Log this access
            if request:
                log_meta_activity(
                    user_id=current_user.user_id,
                    action="download_export",
                    query_params={"export_id": export_id, "filename": filename},
                    ip_address=request.client.host
                )
            
            return FileResponse(
                path=file_path,
                filename=filename,
                media_type="application/octet-stream"
            )
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Export with ID {export_id} not found"
    )


@router.post("/export/verify", response_model=Dict[str, Any])
async def verify_export_endpoint(
    export_file_path: str,
    verification_file_path: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    request: Request = None
):
    """Verify an exported log file against its verification metadata"""
    if not os.path.exists(export_file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Export file not found"
        )
    
    # Log this verification attempt
    if request:
        log_meta_activity(
            user_id=current_user.user_id,
            action="verify_export",
            query_params={"export_file": os.path.basename(export_file_path)},
            ip_address=request.client.host
        )
    
    # Verify the export
    result = verify_export(export_file_path, verification_file_path)
    
    return result
