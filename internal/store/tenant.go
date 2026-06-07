package store

import (
	"strings"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func sameTenant(recordTenant string, tenant string) bool {
	return tenantOrDefault(recordTenant) == tenantOrDefault(tenant)
}

func tenantOrDefault(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	return value
}

func filterEventsByTenant(events []domain.Event, tenant string) []domain.Event {
	if tenant == "" {
		return append([]domain.Event(nil), events...)
	}
	tenant = tenantOrDefault(tenant)
	filtered := make([]domain.Event, 0, len(events))
	for _, event := range events {
		if sameTenant(event.Tenant, tenant) {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func filterAlertsByTenant(alerts []domain.Alert, tenant string) []domain.Alert {
	if tenant == "" {
		return append([]domain.Alert(nil), alerts...)
	}
	tenant = tenantOrDefault(tenant)
	filtered := make([]domain.Alert, 0, len(alerts))
	for _, alert := range alerts {
		if sameTenant(alert.Tenant, tenant) {
			filtered = append(filtered, alert)
		}
	}
	return filtered
}

func filterActionsByTenant(actions []domain.ResponseAction, tenant string) []domain.ResponseAction {
	if tenant == "" {
		return append([]domain.ResponseAction(nil), actions...)
	}
	tenant = tenantOrDefault(tenant)
	filtered := make([]domain.ResponseAction, 0, len(actions))
	for _, action := range actions {
		if sameTenant(action.Tenant, tenant) {
			filtered = append(filtered, action)
		}
	}
	return filtered
}

func filterAuditsByTenant(audits []domain.AuditEvent, tenant string) []domain.AuditEvent {
	if tenant == "" {
		return append([]domain.AuditEvent(nil), audits...)
	}
	tenant = tenantOrDefault(tenant)
	filtered := make([]domain.AuditEvent, 0, len(audits))
	for _, audit := range audits {
		if sameTenant(audit.Tenant, tenant) {
			filtered = append(filtered, audit)
		}
	}
	return filtered
}

func filterAssetsByTenant(assets []domain.Asset, tenant string) []domain.Asset {
	if tenant == "" {
		return append([]domain.Asset(nil), assets...)
	}
	tenant = tenantOrDefault(tenant)
	filtered := make([]domain.Asset, 0, len(assets))
	for _, asset := range assets {
		if sameTenant(asset.Tenant, tenant) {
			filtered = append(filtered, asset)
		}
	}
	return filtered
}
