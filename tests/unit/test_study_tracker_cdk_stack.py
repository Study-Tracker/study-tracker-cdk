import aws_cdk as core
import aws_cdk.assertions as assertions

from cdk_templates.study_tracker_application_stack import StudyTrackerCdkStack

# example tests. To run these tests, uncomment this file along with the example
# resource in study_tracker_cdk/study_tracker_cdk_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = StudyTrackerCdkStack(app, "study-tracker-cdk")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
