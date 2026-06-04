#!/bin/bash
NAMESPACE="prowler"
echo "=========================================="
echo "       PROWLER HEALTH CHECK               "
echo "=========================================="

echo -e "\n--- 1. Pod Status ---"
kubectl get pods -n $NAMESPACE

echo -e "\n--- 2. Load Balancer Status ---"
LB_IP=$(kubectl get svc prowler-lb -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

if [ -z "$LB_IP" ]; then
    echo "⏳ Load Balancer IP is still provisioning. Wait 1-2 minutes and run again."
else
    echo "✅ Load Balancer IP: $LB_IP"
    
    echo -e "\n--- 3. Web Traffic Checks ---"
    
    # Test UI (Should return 200 OK)
    UI_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://$LB_IP:3000)
    if [ "$UI_STATUS" == "200" ] || [ "$UI_STATUS" == "304" ]; then
        echo "✅ UI (Port 3000): HTTP $UI_STATUS (Successfully responding)"
    else
        echo "❌ UI (Port 3000): HTTP $UI_STATUS (Not responding correctly)"
    fi

    # Test API (Might return 401/403/404 depending on auth, but shouldn't return 000/500)
    API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://$LB_IP:8080/api/v1/)
    if [ "$API_STATUS" != "000" ] && [ "$API_STATUS" != "500" ]; then
        echo "✅ API (Port 8080): HTTP $API_STATUS (Successfully responding)"
    else
        echo "❌ API (Port 8080): HTTP $API_STATUS (Connection failed or Internal Server Error)"
    fi
fi

echo -e "\n--- 4. Checking API Logs for Hidden Errors ---"
API_POD=$(kubectl get pods -n $NAMESPACE -l app=prowler-api -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$API_POD" ]; then
    ERROR_COUNT=$(kubectl logs $API_POD -n $NAMESPACE --tail=50 | grep -iE "traceback|exception|improperlyconfigured" | wc -l)
    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo "⚠️  Found potential Python errors in API logs. To investigate, run:"
        echo "   kubectl logs $API_POD -n $NAMESPACE"
    else
        echo "✅ No obvious Python crash tracebacks in the API logs."
    fi
fi
echo "=========================================="
