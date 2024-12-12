from app import app, db, User, Assessment, Question
from werkzeug.security import generate_password_hash
import json

def create_assertiveness_assessment():
    with app.app_context():
        # Create admin user if not exists
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(username="admin")
            admin.set_password("admin123")
            admin.is_admin = True
            db.session.add(admin)
            db.session.flush()

        # Create assertiveness assessment
        assessment = Assessment(
            title="Assertiveness Assessment",
            description="""This assessment helps evaluate your level of assertiveness in various situations. 
            Assertiveness is the ability to express yourself effectively and stand up for your point of view while 
            respecting the rights and beliefs of others. The test will help you understand your current assertiveness 
            level and areas for improvement.""",
            creator_id=admin.id
        )
        db.session.add(assessment)
        db.session.flush()

        # Questions for the assessment
        questions = [
            {
                "content": "When someone criticizes you unfairly, how do you typically respond?",
                "type": "multiple_choice",
                "options": [
                    "I remain silent to avoid conflict",
                    "I defend myself calmly with facts",
                    "I become angry and defensive",
                    "I try to change the subject"
                ]
            },
            {
                "content": "If a friend repeatedly borrows money without repaying, would you address the issue?",
                "type": "multiple_choice",
                "options": [
                    "Yes, I would have an honest conversation about it",
                    "No, I would avoid mentioning it",
                    "I would stop lending but not discuss it",
                    "I would make excuses to not lend anymore"
                ]
            },
            {
                "content": "In group discussions, how often do you express your opinion even if it differs from others?",
                "type": "multiple_choice",
                "options": [
                    "Always - I speak up regardless of others' opinions",
                    "Often - When I feel strongly about the topic",
                    "Sometimes - Only when I feel very confident",
                    "Rarely - I usually agree with the majority"
                ]
            },
            {
                "content": "When someone cuts in front of you in a line, what is your typical reaction?",
                "type": "multiple_choice",
                "options": [
                    "Politely point out that there is a line",
                    "Say nothing but feel frustrated",
                    "Confront them aggressively",
                    "Let them cut and avoid confrontation"
                ]
            },
            {
                "content": "How do you handle it when you need to say 'no' to someone?",
                "type": "multiple_choice",
                "options": [
                    "Say no clearly and directly",
                    "Make up excuses",
                    "Say yes even though I don't want to",
                    "Avoid the person or situation"
                ]
            },
            {
                "content": "When receiving poor service at a restaurant, how do you respond?",
                "type": "multiple_choice",
                "options": [
                    "Raise concerns politely with the server",
                    "Say nothing but leave a poor tip",
                    "Complain loudly and demand to see a manager",
                    "Never return to the restaurant"
                ]
            },
            {
                "content": "How comfortable are you with receiving compliments?",
                "type": "multiple_choice",
                "options": [
                    "Accept them graciously",
                    "Deflect or minimize them",
                    "Feel very uncomfortable",
                    "Reject them outright"
                ]
            },
            {
                "content": "When you disagree with your boss's idea in a meeting, what do you typically do?",
                "type": "multiple_choice",
                "options": [
                    "Express disagreement respectfully with alternatives",
                    "Stay silent and go along with it",
                    "Argue strongly against it",
                    "Agree in the meeting but complain to colleagues later"
                ]
            },
            {
                "content": "How do you handle it when someone borrows your belongings without asking?",
                "type": "multiple_choice",
                "options": [
                    "Discuss it directly with them",
                    "Drop subtle hints about it",
                    "Get visibly angry and confront them",
                    "Say nothing but feel resentful"
                ]
            },
            {
                "content": "When you achieve something significant, how do you share it with others?",
                "type": "multiple_choice",
                "options": [
                    "Share it confidently when appropriate",
                    "Wait for others to notice",
                    "Don't mention it at all",
                    "Constantly talk about it"
                ]
            }
        ]

        # Add questions to the assessment
        for q in questions:
            question = Question(
                content=q["content"],
                question_type=q["type"],
                options=json.dumps(q["options"]) if "options" in q else None,
                assessment_id=assessment.id
            )
            db.session.add(question)

        db.session.commit()
        print("Assertiveness assessment created successfully!")

if __name__ == "__main__":
    create_assertiveness_assessment()
