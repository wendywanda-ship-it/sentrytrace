from django.db import migrations


ROLE_CATALOG = (
    ("Administrator", "Manage users, roles, policies, and security oversight."),
    ("Staff", "General organizational staff role; access is configured through ACLs."),
    ("Department Manager", "Department leadership; access is configured through ACLs."),
    ("Executive", "Executive leadership; access is configured through ACLs."),
    ("Human Resources", "Human resources; access is configured through ACLs."),
    ("IT Administrator", "IT operations; access is configured through ACLs."),
    ("Security Analyst", "Security operations and analysis; access is configured through ACLs."),
    ("Security Officer", "Security oversight; access is configured through ACLs."),
    ("Auditor", "Review and audit responsibilities; access is configured through ACLs."),
    ("Compliance Officer", "Compliance responsibilities; access is configured through ACLs."),
    ("Legal Officer", "Legal responsibilities; access is configured through ACLs."),
    ("Finance Officer", "Finance responsibilities; access is configured through ACLs."),
    ("Researcher", "Research data access subject to configured ACLs."),
    ("Project Manager", "Project coordination; access is configured through ACLs."),
    ("Operations", "Operational responsibilities; access is configured through ACLs."),
    ("Other", "Use for an organizational role outside the standard catalog."),
)


def add_catalog_roles(apps, schema_editor):
    Role = apps.get_model("authentication", "Role")
    db = schema_editor.connection.alias
    for name, description in ROLE_CATALOG:
        Role.objects.using(db).get_or_create(
            role_name=name,
            defaults={"description": description},
        )


class Migration(migrations.Migration):
    dependencies = [("authentication", "0005_accesslog_details_accesslog_outcome_and_more")]

    operations = [migrations.RunPython(add_catalog_roles, migrations.RunPython.noop)]
