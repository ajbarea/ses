# Machine Learning Pipeline Explanation

This document provides an overview of the machine learning pipeline implemented in `ml_trainer.py`. The system is designed to predict a numerical security score and classify the security posture into a qualitative grade based on various system metrics.

## Data Preprocessing (`SecurityDataset`)

The pipeline begins by loading and transforming raw data from a CSV file into a format suitable for training a neural network. This is handled by the `SecurityDataset` class.

- **Feature and Target Separation**: The dataset distinguishes between input features (e.g., `patch_status`, `ports_count`) and target variables (`target_score`, `target_grade`). Feature columns are identified as those not starting with `target_`.

- **Categorical Feature Encoding**: Categorical features with text values are converted into numerical representations using `sklearn.preprocessing.LabelEncoder`. Each unique category is assigned a unique integer.

- **Numerical Feature Scaling**: Numerical features are standardized using `sklearn.preprocessing.StandardScaler` to have a mean of 0 and a standard deviation of 1.

- **Target Grade Encoding (Optional)**: If a `target_grade` column exists, it is converted into numerical labels using `LabelEncoder`.

## Multi-Task Neural Network (`SecurityNN`)

The core of the pipeline is the `SecurityNN`, a PyTorch neural network that predicts both a security score and a security grade.

- **Shared Base Layers**: The model has a common set of layers that process the input features.

- **Two Output Heads**:
  1. **Score Predictor (Regression Head)**: Predicts the numerical `target_score` and uses a `Sigmoid` activation function, scaling the output to a range between 0 and 100.
  2. **Grade Classifier (Classification Head)**: Predicts the `target_grade` and outputs raw scores (logits) for each possible grade category.

This multi-task architecture enables the model to learn shared representations useful for both tasks.

## Training Process (`train_model`)

The `train_model` function manages the training loop.

- **Loss Functions**:

  - **Mean Squared Error (`nn.MSELoss`)**: Measures the difference between predicted and actual scores.
  - **Cross-Entropy Loss (`nn.CrossEntropyLoss`)**: Used for the grade classification task.

- **Combined Loss**: The total loss is a weighted sum of the score loss and the grade loss (`total_loss = score_loss + 0.3 * grade_loss`).

- **Optimization**: The `Adam` optimizer updates the model's weights based on the calculated loss.

## Model Evaluation (`evaluate_security_model`)

The `evaluate_security_model` function assesses the model's performance on a test dataset.

- **Metrics**: Calculates Mean Squared Error (MSE), Mean Absolute Error (MAE), Root Mean Squared Error (RMSE), and R² for score predictions.

- **Grade Accuracy**: Measures the percentage of correctly classified grades.

- **Expert System Consistency**: This is a custom metric that measures the logical consistency between the model's two predictions. It checks if the predicted numerical score falls within the predefined score range for the predicted grade. For example, if the model predicts a grade of "Excellent", this metric checks if the predicted score is between 90 and 100. A high consistency score indicates that the model's two outputs are well-aligned.

## Alternative Model (`_train_sklearn_model`)

The pipeline also includes the capability to train a simple `sklearn.linear_model.LinearRegression` model. This serves as a quick baseline to compare against the more complex neural network, ensuring that the added complexity of the `SecurityNN` provides a tangible performance benefit.

This simple linear model primarily focuses on a single-task score prediction. While useful as a baseline, it is generally outperformed by the `SecurityNN` because:

- It can only model linear relationships between features and the security score.
- It does not utilize categorical features, which can contain valuable predictive information.
- It is a single-task model, only predicting the score without the accompanying grade classification.

The `SecurityNN` represents a more advanced and capable solution for this problem.
