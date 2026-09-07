import os
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./history.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan_runs = relationship("ScanRun", back_populates="target")

class ScanRun(Base):
    __tablename__ = "scan_runs"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, unique=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    scanner_tools_used = Column(String)
    
    target = relationship("Target", back_populates="scan_runs")
    findings = relationship("VulnerabilityFinding", back_populates="scan_run")

class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"))
    fingerprint = Column(String, index=True)
    tool = Column(String)
    vulnerability_title = Column(String)
    severity = Column(String)
    description = Column(String)
    evidence = Column(String, nullable=True)
    reference = Column(String, nullable=True)
    status = Column(String) # New, Persistent, Resolved
    
    scan_run = relationship("ScanRun", back_populates="findings")

def init_db():
    Base.metadata.create_all(bind=engine)
