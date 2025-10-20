from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Float, BigInteger, UniqueConstraint, func
)
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    __table_args__ = (UniqueConstraint('email', name='uq_user_email'),)
    devices = relationship("Device", back_populates="owner", cascade="all, delete-orphan")
    files   = relationship("File",   back_populates="owner", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    capacity_gb = Column(Float, default=100.0)
    is_online = Column(Boolean, default=True)
    last_sync = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    device_token = Column(String, unique=True, index=True, nullable=True)
    platform     = Column(String, default="unknown")
    root_path    = Column(String, nullable=True)
    free_bytes   = Column(BigInteger, default=0)
    last_seen = Column(DateTime)                   
    total_bytes = Column(BigInteger, default=0)    
    used_bytes  = Column(BigInteger, default=0)      

    owner = relationship("User", back_populates="devices")
    assignments = relationship("FileAssignment", back_populates="device", cascade="all, delete-orphan")

    # NEW: heartbeat history
    heartbeats = relationship("DeviceHeartbeat", back_populates="device", cascade="all, delete-orphan")


class DeviceHeartbeat(Base):
    __tablename__ = "device_heartbeats"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    free_bytes = Column(BigInteger, default=0, nullable=False)
    platform   = Column(String, default="unknown")
    root_path  = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    device = relationship("Device", back_populates="heartbeats")


class File(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    mime_type = Column(String, default="application/octet-stream")
    size_bytes = Column(BigInteger, default=0)
    path = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="files")
    assignments = relationship("FileAssignment", back_populates="file", cascade="all, delete-orphan")


class FileAssignment(Base):
    __tablename__ = "file_assignments"
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)

    file = relationship("File", back_populates="assignments")
    device = relationship("Device", back_populates="assignments")

    __table_args__ = (UniqueConstraint("file_id", "device_id", name="uix_file_device"),)
