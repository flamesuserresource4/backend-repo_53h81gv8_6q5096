"""
Database Schemas for Kick Start Visuals

Each Pydantic model maps to a MongoDB collection (lowercased class name).
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt hashed password")
    phone: Optional[str] = Field(None, description="Phone number")
    is_admin: bool = Field(False, description="Admin role flag")

class Project(BaseModel):
    user_id: Optional[str] = Field(None, description="Reference to user _id as string")
    name: str = Field(..., description="Customer name")
    email: str = Field(..., description="Customer email")
    phone: Optional[str] = Field(None, description="Customer phone")
    selected_service: str = Field(..., description="Selected service")
    description: str = Field(..., description="Project description")
    budget: Optional[str] = Field(None, description="Optional budget")
    status: str = Field("Pending", description="Project status")
    notes: Optional[str] = Field(None, description="Admin notes")
    files: List[dict] = Field(default_factory=list, description="List of uploaded file metadata")

class Message(BaseModel):
    project_id: str = Field(..., description="Associated project id")
    sender_id: Optional[str] = Field(None, description="User id of sender if available")
    sender_role: str = Field(..., description="'admin' or 'customer'")
    content: str = Field(..., description="Message text")
    created_at: Optional[datetime] = None
