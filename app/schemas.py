from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class Credentials(BaseModel):
    username: str
    secret_key: str


class GetAllowedDataForm(BaseModel):
    username: str
    secret_key: str
    type: str


class SearchRequestData(BaseModel):
    search_id: Optional[str]
    query: Optional[str]
    time_range: Optional[str]
    repos: Optional[List[str]]
    limit: Optional[int] = 100
    client_name: Optional[str]
    timeout: Optional[int]


class SearchForm(BaseModel):
    username: str
    secret_key: str
    requestData: str


class IncidentRequestBody(BaseModel):
    username: str
    secret_key: str
    requestData: Dict[str, Any]


class AddCommentsPayload(BaseModel):
    version: str
    states: List[Dict[str, Any]]


class AssignIncidentPayload(BaseModel):
    version: str
    incident_ids: List[str]
    new_assignee: str


class ResolveIncidentPayload(BaseModel):
    version: str
    incident_ids: List[str]


class AlertRulePayload(BaseModel):
    id: Optional[str]
    search_params: Dict[str, Any]
    incident_condition: Dict[str, Any]
    taxonomy: Dict[str, Any]
    incident_ownership: Dict[str, Any]
    incident_display_data: Dict[str, Any]
    foureyes: Dict[str, Any]
    name: str
    description: Optional[str] = ""


class IdsPayload(BaseModel):
    ids: List[str]


class HttpNotificationPayload(BaseModel):
    type: str
    http_url: str
    http_request_type: str
    http_querystring: Optional[str] = ""
    notify_http: Optional[bool] = True
    http_format_query: Optional[str] = ""
    http_body: Optional[str] = ""
    protocol: Optional[str] = "HTTPS"
    dispatch_option: Optional[str] = "auto"
    http_header: Optional[Dict[str, str]] = {}
    http_threshold_value: Optional[int] = 0
    http_threshold_option: Optional[str] = "minute"
    ids: List[str]


class UserDefinedImportResponse(BaseModel):
    success: bool
    summary: str
    message: str
