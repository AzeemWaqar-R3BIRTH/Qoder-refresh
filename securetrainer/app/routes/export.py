from flask import Blueprint, request, jsonify, Response
from app.models.analytics_model import export_analytics_for_csv
import csv
import io
import os

export_bp = Blueprint('export', __name__)

def is_admin(token):
    return token == os.getenv("ADMIN_TOKEN")

@export_bp.route('/csv', methods=['GET'])
def export_csv():
    token = request.headers.get('Authorization')
    if not is_admin(token):
        return jsonify({'error': 'Unauthorized'}), 403

    data = export_analytics_for_csv()

    # Stream CSV
    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)

    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=analytics.csv"})
