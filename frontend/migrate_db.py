from app import app, db, User, Assessment, Question, AssessmentResponse
from datetime import datetime
import json

def migrate_db():
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()
        
        # Create admin user
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

        # Create assertiveness assessment
        assertiveness = Assessment(
            title='Assertiveness Assessment',
            description='Evaluate your assertiveness skills in various situations. This assessment will help you understand your communication style and provide recommendations for improvement.',
            creator_id=admin.id
        )
        db.session.add(assertiveness)
        db.session.flush()  # Get the assessment ID

        # Add questions
        questions = [
            {
                'content': 'When someone criticizes your work unfairly, how do you typically respond?',
                'type': 'multiple_choice',
                'options': ['I remain silent to avoid conflict', 'I defend myself calmly with facts', 'I become angry and defensive', 'I try to change the subject']
            },
            {
                'content': 'If a friend repeatedly borrows money without repaying, would you address this issue?',
                'type': 'multiple_choice',
                'options': ['Yes, I would have an honest conversation about it', 'No, I would avoid mentioning it', 'I would stop lending but not discuss it', 'I would make excuses to not lend anymore']
            },
            {
                'content': 'How often do you express your opinion in group discussions?',
                'type': 'multiple_choice',
                'options': ['Always - I speak up regardless of others\' opinions', 'Often - When I feel strongly about the topic', 'Sometimes - Only when I feel very confident', 'Rarely - I usually agree with the majority']
            },
            {
                'content': 'When someone cuts in line in front of you, what do you typically do?',
                'type': 'multiple_choice',
                'options': ['Politely point out that there is a line', 'Say nothing but feel frustrated', 'Confront them aggressively', 'Let them cut and avoid confrontation']
            },
            {
                'content': 'How do you handle requests that you don\'t want to fulfill?',
                'type': 'multiple_choice',
                'options': ['Say no clearly and directly', 'Make up excuses', 'Say yes even though I don\'t want to', 'Avoid the person or situation']
            },
            {
                'content': 'If your meal at a restaurant isn\'t prepared as requested, what would you do?',
                'type': 'multiple_choice',
                'options': ['Raise concerns politely with the server', 'Say nothing but leave a poor tip', 'Complain loudly and demand to see a manager', 'Never return to the restaurant']
            },
            {
                'content': 'How do you typically handle compliments?',
                'type': 'multiple_choice',
                'options': ['Accept them graciously', 'Deflect or minimize them', 'Feel very uncomfortable', 'Reject them outright']
            },
            {
                'content': 'During a team meeting, how do you respond when you disagree with a proposed idea?',
                'type': 'multiple_choice',
                'options': ['Express disagreement respectfully with alternatives', 'Stay silent and go along with it', 'Argue strongly against it', 'Agree in the meeting but complain to colleagues later']
            },
            {
                'content': 'If a colleague\'s behavior is bothering you, what would you do?',
                'type': 'multiple_choice',
                'options': ['Discuss it directly with them', 'Drop subtle hints about it', 'Get visibly angry and confront them', 'Say nothing but feel resentful']
            },
            {
                'content': 'When you achieve something significant at work, how do you handle it?',
                'type': 'multiple_choice',
                'options': ['Share it confidently when appropriate', 'Wait for others to notice', 'Don\'t mention it at all', 'Constantly talk about it']
            }
        ]

        for q_data in questions:
            question = Question(
                content=q_data['content'],
                question_type=q_data['type'],
                options=json.dumps(q_data['options']),
                assessment_id=assertiveness.id
            )
            db.session.add(question)

        db.session.commit()
        print("Database migrated successfully!")

if __name__ == '__main__':
    migrate_db()
